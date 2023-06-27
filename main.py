import shodan, nmap3, tkintermapview, customtkinter, threading, time, os, sys, re, json, requests, asyncio, aiohttp
from tkinter import IntVar, Checkbutton, Button, Label, Frame, Scrollbar, messagebox, simpledialog
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter.ttk import *
from tkinter import *

def check_Root():
    if os.geteuid() == 0:
        print('Running as root ✔️')
    else:
        sys.exit('Must run script as root user, to allow nmap functions to work')

def check_API():
    global api_key

    def prompt_user():
        print('Enter the API')
        dialog = customtkinter.CTkInputDialog(title='Input', text='Enter shodan api key:')
        data = dialog.get_input()
        with open('.env', 'w') as f:
            f.write('API_KEY=' + str(data))
            f.close()

    if os.path.exists('.env'):
        secrets = dotenv_values('.env')
        api_data  = bool(re.search(r'\d', str(secrets['API_KEY'])))
        if api_data == True:
            secrets = dotenv_values('.env')
            api_key = str(secrets['API_KEY'])
        elif api_data == False:
            prompt_user()
    else:
        prompt_user()
        secrets = dotenv_values('.env')
        api_key = str(secrets['API_KEY'])

global api_key
api_key = ''
   
# ------------------ Namp window ----------------- #

def nmap_window():
    window = Toplevel(root, background='#515b66')
    window.title('Nmap Window')
    window.geometry('600x650')
    window.resizable(False, False)

    frame_background_highlight = customtkinter.CTkFrame(master=window, width=520, height=510, fg_color='white')
    frame_background_highlight.place(x=40, y=5)

    frame = customtkinter.CTkFrame(master=window, width=500, height=500, fg_color='#515b66')
    frame.place(x=50, y=10)

    fpack = ("MS Serif", 20)
    text = customtkinter.CTkTextbox(master=frame)
    text.pack()
    text.configure(font=fpack, fg_color='white', text_color='black', width=500, height=500)

    check_Var = customtkinter.StringVar(value="off")

    C4 = customtkinter.CTkCheckBox(window, hover_color='green', fg_color='green',border_color='white', text_color='white', checkmark_color='white', text="Save Results", command=lambda: [checkbox_event()], variable=check_Var, onvalue="on", offvalue="off")
    C4.place(x=200, y=590)

    # OS detection scan
    C1 = customtkinter.CTkButton(window, hover_color='red', fg_color='green', text='OS Detection', command=lambda:[os_detect(IP_Entry.get())])
    C1.place(x=50, y=550)

    # DNS bruteforce
    C2 = customtkinter.CTkButton(window, hover_color='red', fg_color='green', text='DNS bruteforce', command=lambda:[dns_brute()])
    C2.place(x=50, y=590)
        
    # UDP scan button
    C3 = customtkinter.CTkButton(window, hover_color='red', fg_color='green', text="Version detection", command=lambda:[version_detc(IP_Entry.get())])
    C3.place(x=200, y=550)

    def checkbox_event():
        print('The checkbox has been clicked: ' + check_Var.get())
    
    def version_detc(IP):
        nmap = nmap3.Nmap()
        results = nmap.nmap_version_detection(str(IP))
        if check_Var.get() == 'on': 
            output = ""
            for data in results[str(IP)]['ports']:
                output += data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'] + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)
            save_json_data(IP, results, 'version_detection')
        elif check_Var.get() == 'off':
            output = ""
            for data in results[str(IP)]['ports']:
                output += data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'] + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)

    def os_detect(IP):
        print('OS Detect script running')
        nmap = nmap3.Nmap()
        results = nmap.nmap_os_detection(IP)
        if check_Var.get() == 'on':
            output = ""
            for data in results[str(IP)]["osmatch"]:
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)
            save_json_data(IP, results, 'os_detection')
        elif check_Var.get() == 'off':
            output = ""
            for data in results[str(IP)]["osmatch"]:
                print('Outputting to screen')
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)

    def dns_brute():
        data = customtkinter.CTkInputDialog(text='Enter the domain name', title='Domain')
        target = data.get_input()
        nmap = nmap3.Nmap()
        results = nmap.nmap_dns_brute_script(target)
        if check_Var.get() == 'on':
            output = ""
            for data in results[0:10]:
                output += data['hostname'] + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)
            save_json_data(target, results, 'dns-bruteforce.json')
        elif check_Var.get() == 'off':
            output = ""
            print('Scanning without saving...')
            for data in results[0:10]:
                output += data['hostname'] + '\n'
            text.delete("0.0", "end")
            text.insert("0.0", output)
# ------------------ Namp window ----------------- #

# ------------------ Shodan Search Function ---------------------#

def loading_bar(IP):
    style = Style()
    style.theme_use('alt')
    style.configure("Horizontal.TProgressbar", troughcolor ='green', background='white')
    progress = Progressbar(root, mode="determinate", style="Horizontal.TProgressbar", orient="horizontal", length=120)
    progress.place(x=830, y=765)
    progress['value'] = 25
    progress.update_idletasks()
    P10 = Process(target=shodan_search(IP))
    P10.start()
    P11 = Process(target=display_shodan_map(IP))
    P11.start()
    loop = asyncio.new_event_loop()
    progress['value'] = 50
    progress.update_idletasks()
    loop.run_until_complete(cve_info(IP)) 
    progress['value'] = 100
    progress.update_idletasks()

async def fetch_multiple(session, urls):
    print('Fetch Multiple is running')
    tasks = [fetch(session, url) for url in urls]
    responses = await asyncio.gather(*tasks)
    return responses

async def fetch(session, url):
    print('Fetch is running')
    async with session.get(url) as response:
        return await response.json()

async def cve_info(IP):
    fpack = customtkinter.CTkFont(
        family="Times",
        size=20,
        weight="bold",
        slant="roman",
    )
    try:
        output = []
        response_data = []
        host = api.host(str(IP))
        cve_names = [cve for cve in host['vulns'][0:5]] # Limit to only 5 searches (5 cves)
        urls = ['http://api.cvesearch.com/search?q=' + item for item in cve_names]
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=None)) as session:
            responses = await fetch_multiple(session, urls)
            for response in responses: # this is being converted into a dict.
                response_data = response
                for cve in cve_names:
                    try:
                        print(str(cve) + response_data['response'][str(cve).lower()]['basic']['description'] + '\n') 
                        output.append(str(cve) + str(response_data['response'][str(cve).lower()]['basic']['description']) + '\n')
                    except KeyError:
                        pass
            # Add to frame here
            cve_text = Text(Panel3_information, background='white')
            cve_text.pack(fill="both", expand=True)
            cve_text.insert(END, ''.join(output))
    except shodan.exception.APIError:
        pass
    except KeyError:
        cve_label = customtkinter.CTkLabel(Panel3_information, font=fpack, text="CVE's not found...", text_color='white', fg_color='transparent')
        cve_label.pack()

def shodan_search(IP):
    print('Shodan search running')
    fpack = customtkinter.CTkFont(
        family="Times",
        size=20,
        weight="bold",
        slant="roman",
        )

    try:
        host = api.host(IP)
        ip, banner, port, city, domains, asn, coordinates, coordinates2 = [],[],[],[],[],[],[],[]
        for items in host['data']:
            ip.append(items['ip_str'])
            banner.append(items['data'])
            port.append(items['port'])
            city.append(host.get('city', 'n/a'))
            domains.append(host.get('domain', 'n/a'))
            asn.append(items['asn'])
            coordinates.append(items['location']['latitude'])
            coordinates2.append(items['location']['longitude'])

        for index, (a, b, c, d, e, f, g) in enumerate(zip(ip, port, city, domains, asn, coordinates, coordinates2)):
            customtkinter.CTkLabel(master=Panel1_results, font=fpack, fg_color='transparent', text_color='white', text='IP: ' + str(a)).place(x=10, y=20)
            customtkinter.CTkLabel(master=Panel1_results,  font=fpack, fg_color='transparent', text_color='white', text='Port: ' + str(b)).place(x=10, y=60)
            customtkinter.CTkLabel(master=Panel1_results,  font=fpack, fg_color='transparent', text_color='white', text='City: ' + str(c)).place(x=10, y=100)
            customtkinter.CTkLabel(master=Panel1_results,  font=fpack, fg_color='transparent', text_color='white', text='Domains: ' + str(d)).place(x=10, y=150)
            customtkinter.CTkLabel(master=Panel1_results,  font=fpack, fg_color='transparent', text_color='white', text='ASN: ' + str(e)).place(x=10, y=200)
            customtkinter.CTkLabel(master=Panel1_results,  font=fpack, fg_color='transparent', text_color='white', text='coordinates: ' + str(f) + ' ' + str(g)).place(x=10, y=250)
    except shodan.exception.APIError:
        pass

def display_shodan_map(IP):
    print('Shodan Map Running')
    try:
        host = api.host(IP)
        coordinates1, coordinates2 = [],[]
        for items in host['data']:
            coordinates1.append(items['location']['latitude'])
            coordinates2.append(items['location']['longitude'])
            print(coordinates1, coordinates2)
        for index, (a, b) in enumerate(zip(coordinates1, coordinates2)):
            # segmentation fault (core dumped) - Here
            map_widget = tkintermapview.TkinterMapView(Panel2_maps, corner_radius=0)
            map_widget.set_position(a, b)
            map_widget.set_marker(a, b, text=str(IP))
            map_widget.set_tile_server("https://a.tile.openstreetmap.org/{z}/{x}/{y}.png", max_zoom=22)
            map_widget.grid(row=0, column=0, sticky="nsew")
            
            Panel2_maps.grid_rowconfigure(0, weight=1)
            Panel2_maps.grid_columnconfigure(0, weight=1)
    except shodan.exception.APIError:
            print('You must enter an API key!')
            messagebox.showwarning('API Issue', message='Invalid API!!')

# --------------- Functions for extra windows ---------------- #
def nwindow(): # Nmap window
    P1 = nmap_window(IP_Entry.get())
    P1.mainloop()
T1 = threading.Thread(target=nmap_window, daemon=True)
# ------------------------------- Main Window Bellow --------------------------------------------

root = Tk()
root.geometry("1000x800")
root.title("Shomaps")
fpack = ("MS Serif", 20)

# Framed windows
pw_windows = Panedwindow(root, orient='horizontal')
Panel1_results = LabelFrame(pw_windows, font=fpack, relief='flat', text="General Information", foreground='#62ff00', background='#515b66', height=440)
Panel2_maps = LabelFrame(pw_windows, font=fpack, text="Map", relief='flat',  foreground='#62ff00', background='#515b66')

# Frame windows extension
pw_windows.add(Panel1_results, weight=50)
pw_windows.add(Panel2_maps, weight=50)
pw_windows.pack(fill='both', expand=False)

# Veritcal frame windows - More information window
pg_windows = Panedwindow(root, orient='vertical')
Panel3_information = LabelFrame(pg_windows, font=fpack, text="More Information", relief='flat', foreground='#62ff00', background='#515b66', height=350)
pg_windows.add(Panel3_information, weight=50)
pg_windows.pack(side=BOTTOM, fill='x', expand=False)

# Entry box
IP_Entry = Entry(master=root, text="Enter IP Address", width=30)
IP_Entry.place(x=540, y=775, anchor='center')

# Search button
search_button = customtkinter.CTkButton(master=root, hover_color='red', fg_color='green', text='Shodan Search', command=lambda:[loading_bar(IP_Entry.get())])
search_button.place(x=750, y=775, anchor='center')

# Namp scan button
scan_nmap = customtkinter.CTkButton(master=root, hover_color='red', fg_color='green', text='Perform Nmap Scan', command=lambda:[T1.start()])
scan_nmap.place(x=250, y=760)

def close_window():
    print('You clicked the Exit button')
    sys.exit("Closing window")

if __name__ == '__main__':
     check_Root()
     check_API()
     api = shodan.Shodan(str(api_key))
     root.configure(background='white')
     root.protocol("WM_DELETE_WINDOW", close_window)
     root.resizable(False, False)
     root.mainloop()

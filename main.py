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

class Nwindow(customtkinter.CTk):
    IP = ''

    def __init__(self, IP):
        super().__init__()
        self.geometry('600x650')
        self.title('Nmap Window')

        self.IP = IP

        self.frame_background_highlight = customtkinter.CTkFrame(master=self, width=520, height=510, fg_color='white')
        self.frame_background_highlight.place(x=40, y=5)
        
        self.frame = customtkinter.CTkFrame(master=self, width=500, height=500, fg_color='#515b66')
        self.frame.place(x=50, y=10)

        # Text box
        fpack = ("MS Serif", 20)
        self.text = customtkinter.CTkTextbox(master=self.frame,)
        self.text.pack()
        self.text.configure(font=fpack, fg_color='white', text_color='black', width=500, height=500)

        # Save results checkbox value
        self.check_Var = customtkinter.StringVar(value="off") # This will determine if it's been checked.
        
        # Check box
        C4 = customtkinter.CTkCheckBox(self, hover_color='green', fg_color='green',border_color='white', text_color='white', checkmark_color='white', text="Save Results", command=lambda: [self.checkbox_event()], variable=self.check_Var, onvalue="on", offvalue="off")
        C4.place(x=200, y=590)

        # OS detection scan
        C1 = customtkinter.CTkButton(self, hover_color='red', fg_color='green', text='OS Detection', command=lambda: [self.os_detec(str(self.IP))])
        C1.place(x=50, y=550)
        
        # DNS bruteforce
        C2 = customtkinter.CTkButton(self, hover_color='red', fg_color='green', text='DNS bruteforce', command=lambda: [self.dns_brute()])
        C2.place(x=50, y=590)
        
        # UDP scan button [Replacing UDP with version detection scan]
        C3 = customtkinter.CTkButton(self, hover_color='red', fg_color='green', text="Version detection", command=lambda: [self.version_detc(str(IP))])
        C3.place(x=200, y=550)
        
        self.configure(fg_color='#515b66')
        self.resizable(False, False)

    def checkbox_event(self):
        print('The checkbox has been clicked: ' + self.check_Var.get())

    def version_detc(self, IP):
        nmap = nmap3.Nmap()
        results = nmap.nmap_version_detection(str(IP))
        if self.check_Var.get() == 'on': 
            output = ""
            for data in results[str(IP)]['ports']:
                output += data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'] + '\n'
                self.text.insert("0.0", output)
            self.save_json_data(IP, results, 'version_detection')
        elif self.check_Var.get() == 'off':
            output = ""
            for data in results[str(IP)]['ports']:
                output += data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'] + '\n'
            self.text.insert("0.0", output)

    def os_detec(self, IP):
        print('OS Detect script running')
        nmap = nmap3.Nmap()
        results = nmap.nmap_os_detection(IP)
        if self.check_Var.get() == 'on':
            output = ""
            for data in results[str(self.IP)]["osmatch"]:
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
            self.text.insert("0.0", output)
            self.save_json_data(IP, results, 'os_detection')
        elif self.check_Var.get() == 'off':
            output = ""
            for data in results[str(self.IP)]["osmatch"]:
                print('Outputting to screen')
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
            self.text.insert("0.0", output)
    
    def dns_brute(self):
        data = customtkinter.CTkInputDialog(text='Enter the domain name', title='Domain')
        target = data.get_input()
        nmap = nmap3.Nmap()
        results = nmap.nmap_dns_brute_script(target)
        if self.check_Var.get() == 'on':
            output = ""
            for data in results[0:10]:
                output += data['hostname'] + '\n'
            self.text.insert("0.0", output)
            self.save_json_data(target, results, 'dns-bruteforce.json')
        elif self.check_Var.get() == 'off':
            output = ""
            print('Scanning without saving...')
            for data in results[0:10]:
                output += data['hostname'] + '\n'
            self.text.insert("0.0", output)

    def save_json_data(self, IP, data, scan_type):
        json_object = json.dumps(data, indent=4)
        print('Saving to file...')
        with open(str(IP) + scan_type + '.json', 'w') as f:
            f.write(json_object)
            f.close()
# ------------------ Namp window ----------------- #


# ------------------ Shodan Search Function ---------------------#

def loading_bar(IP):
    progress = customtkinter.CTkProgressBar(root, mode="determinate", orientation="horizontal", progress_color='green', fg_color='white', width=120)
    progress.place(x=830, y=765)
    progress['value'] = 50
    progress.update_idletasks()
    time.sleep(1)
    P10 = Process(target=shodan_search(IP))
    P10.start()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(cve_info(IP))
    progress['value'] = 100
    progress.update_idletasks
    time.sleep(1)

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

def shodan_search(IP):
    print('Shodan search running')
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
            Label(master=Panel1_results, text=str(a)).place(x=10, y=20)
            Label(master=Panel1_results, text=str(b)).place(x=10, y=60)
            Label(master=Panel1_results, text=str(c)).place(x=10, y=100)
            Label(master=Panel1_results, text=str(d)).place(x=10, y=150)
            Label(master=Panel1_results, text=str(e)).place(x=10, y=200)
            Label(master=Panel1_results, text=str(f)).place(x=10, y=250)
            Label(master=Panel1_results, text=str(g)).place(x=10, y=300)
    except shodan.exception.APIError:
        print('Invalid API!')
        messagebox.showwarning('API Issue', message='Invalid API!!')

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
def nmap_window(): # Nmap window
    P1 = Nwindow(IP_Entry.get())
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
search_button = customtkinter.CTkButton(master=root, hover_color='red', fg_color='green', text='Shodan Search', command=lambda:[loading_bar(IP_Entry.get()), display_shodan_map(IP_Entry.get())])
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

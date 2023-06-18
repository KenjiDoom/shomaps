import shodan, nmap3, tkintermapview, customtkinter, threading, time, os, sys, dns.resolver, socket, re, json, logging, requests, asyncio, aiohttp
from tkinter import IntVar, Checkbutton, Button, Label, Frame, Scrollbar, messagebox, simpledialog
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter.ttk import *
from tkinter import *

from concurrent.futures import ThreadPoolExecutor

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

# ------------------ More Information ------------$
class moreInfo(customtkinter.CTk):
    IP = ''
    
    def __init__(self, IP):
        super().__init__()
        self.geometry('600x600')
        self.title('More Information')
        
        self.IP = IP
        
        pd_windows = Panedwindow(master=self, orient='vertical')

        # Frame windows
        Panel1_CVE = LabelFrame(pd_windows, relief='flat', text='CVE Information: ' + self.IP, background='white')
        Panel2_DNS = LabelFrame(pd_windows, relief='flat', text='DNS Information: ' + self.IP, background='white')
        
        # CVE Label
        #self.cve_label = Label(master=Panel1_CVE, text='', background='white')
        #self.cve_label.place(y=50, x=50)

        # CVE Text
        self.cve_text = Text(master=Panel1_CVE, background='white')
        self.cve_text.place(x=20, y=20)
        
        # DNS Label
        self.dns_label = Label(master=Panel2_DNS, text='', background='white')
        self.dns_label.place(x=50, y=50)

        # FRame windows extension
        pd_windows.add(Panel1_CVE, weight=50)
        pd_windows.add(Panel2_DNS, weight=50)
        pd_windows.pack(fill='both', expand=True)

        self.resizable(False, False)
    
    async def fetch_multiple(self, session, urls):
        print('Fetch Multiple is running')
        tasks = [self.fetch(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)
        return responses

    async def fetch(self, session, url):
        print('Fetch is running')
        async with session.get(url) as response:
            return await response.json()

    async def cve_info(self, IP):
        output = []
        response_data = []
        host = api.host(str(IP))
        cve_names = [cve for cve in host['vulns'][0:5]] # Limit to only 5 searches (5 cves)
        urls = ['http://api.cvesearch.com/search?q=' + item for item in cve_names]

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=None)) as session:
            responses = await self.fetch_multiple(session, urls)
            for response in responses: # this is being converted into a dict.
                response_data = response
                for cve in cve_names:
                    try:
                        print(str(cve) + response_data['response'][str(cve).lower()]['basic']['description'] + '\n') 
                        output.append(str(cve) + str(response_data['response'][str(cve).lower()]['basic']['description']) + '\n')
                    except KeyError:
                        pass
            self.cve_text.insert(END, str(output))
    
    def dns_info(self):
        def enum_code(domain):
            try:
               for qtype in 'A', 'AAAA', 'MX', 'NS', 'PTR':
                   answer = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
                   if answer.rrset is not None:
                       output = str(answer.rrset) + '\n'
                       self.dns_label.config(text=output)
                       print(output)
            except dns.resolver.NXDOMAIN:
               print('The domain entered doesnt exist, enter your own maunaly') 
        
        data = socket.gethostbyaddr(self.IP)
        domain_name = data[0]
        popup = messagebox.askquestion(title='Right or wrong?', message=f"Is this the right domain? {domain_name}")
        if popup == 'yes':
            enum_code(domain_name) 
        elif popup == 'no':
            target = customtkinter.CTkInputDialog(text='Enter domain name:', title='Domain')
            domain = target.get_input()
            enum_code(domain)

# ------------------ Namp window ----------------- #

class Nwindow(customtkinter.CTk):
    IP = ''

    def __init__(self, IP):
        super().__init__()
        self.geometry('600x650')
        self.title('Nmap Window')

        self.IP = IP

        self.frame = Frame(master=self, width=500, height=500, background='white')
        self.frame.place(x=50, y=10)
        
        self.scroll = Scrollbar(self.frame)
        self.scroll.place(x=470, y=10, height=485, width=20)

        self.text_label = Label(master=self.frame, width=50, text='Empty')
        self.text_label.place(x=50, y=50)
        
        # Save results checkbox
        self.check_Var = customtkinter.StringVar(value="off") # This will determine if it's been checked.
        
        C4 = customtkinter.CTkCheckBox(self, text="Save Results", command=lambda: [self.checkbox_event()], variable=self.check_Var, onvalue="on", offvalue="off")
        C4.place(x=200, y=590)

        # OS detection scan
        C1 = Button(self, text='OS Detection', command=lambda: [self.os_detec(str(self.IP))])
        C1.place(x=50, y=550)
        
        # Dns bruteforce
        C2 = Button(self, text='DNS bruteforce', command=lambda: [self.dns_brute()])
        C2.place(x=50, y=590)
        
        # UDP scan button [Replacing UDP with version detection scan]
        C3 = Button(self, text="Version detection", command=lambda: [self.version_detc(str(IP))])
        C3.place(x=200, y=550)

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
                self.text_label.config(text=output)
            self.save_json_data(IP, results, 'version_detection')
        elif self.check_Var.get() == 'off':
            output = ""
            for data in results[str(IP)]['ports']:
                output += data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'] + '\n'
                self.text_label.config(text=output)

    def os_detec(self, IP):
        print('OS Detect script running')
        nmap = nmap3.Nmap()
        results = nmap.nmap_os_detection(IP)
        if self.check_Var.get() == 'on':
            output = ""
            for data in results[str(self.IP)]["osmatch"]:
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
                self.text_label.config(text=output)
            self.save_json_data(IP, results, 'os_detection')
        elif self.check_Var.get() == 'off':
            output = ""
            for data in results[str(self.IP)]["osmatch"]:
                print('Outputting to screen')
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
                self.text_label.config(text=output)
    
    def dns_brute(self):
        data = customtkinter.CTkInputDialog(text='Enter the domain name', title='Domain')
        target = data.get_input()
        nmap = nmap3.Nmap()
        results = nmap.nmap_dns_brute_script(target)
        if self.check_Var.get() == 'on':
            output = ""
            for data in results[0:10]:
                output += data['hostname'] + '\n'
                self.text_label.config(text=output)
            self.save_json_data(target, results, 'dns-bruteforce.json')
        elif self.check_Var.get() == 'off':
            output = ""
            print('Scanning without saving...')
            for data in results[0:10]:
                output += data['hostname'] + '\n'
                self.text_label.config(text=output)

    def save_json_data(self, IP, data, scan_type):
        json_object = json.dumps(data, indent=4)
        print('Saving to file...')
        with open(str(IP) + scan_type + '.json', 'w') as f:
            f.write(json_object)
            f.close()
# Side-note: Write a function to do all the file writing instead duplicating all the code...

# ------------------ Namp window ----------------- #


# ------------------ Shodan Search Function ---------------------#

def loading_bar(IP):
    progress = Progressbar(root, mode="determinate", length=150)
    progress.place(x=1200, y=765)
    progress['value'] = 50
    progress.update_idletasks()
    time.sleep(1)
    P10 = Process(target=shodan_search(IP))
    P10.start()
    progress['value'] = 100
    progress.update_idletasks
    time.sleep(1)

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

def window_more():
    IP = IP_Entry.get()
    P2 = moreInfo(IP)
    start_time = time.time()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(P2.cve_info(IP))
    print("--- %s seconds ---" % (time.time() - start_time))
    #P2.dns_info()
    P2.mainloop()

T1 = threading.Thread(target=nmap_window, daemon=True)
T2 = threading.Thread(target=window_more, daemon=True)
# ------------------------------- Main Window Bellow --------------------------------------------

root = Tk()
print('Main window running')
root.geometry("1400x800")
root.title("Shomaps")
fpack = ("MS Serif", 20)

# Framed windows
pw_windows = Panedwindow(root, orient='horizontal')
Panel1_results = LabelFrame(pw_windows, font=fpack, relief='flat', text="General Information", background='white')
Panel2_maps = LabelFrame(pw_windows, font=fpack, text="Map", relief='flat', background='white')
# Frame windows extension
pw_windows.add(Panel1_results, weight=50)
pw_windows.add(Panel2_maps, weight=50)
pw_windows.pack(fill='both', expand=True)


IP_Entry = Entry(master=root, text="Enter IP Address", width=30)
IP_Entry.place(x=700, y=775, anchor='center')

search_button = Button(master=root, text='Shodan Search', command=lambda:[loading_bar(IP_Entry.get()), display_shodan_map(IP_Entry.get())])
search_button.place(x=980, y=775, anchor='center')

scan_nmap = Button(master=root, text='Perform Nmap Scan', command=lambda:[T1.start()])
scan_nmap.place(x=150, y=760)

more_results = Button(master=root, text='More Information', command=lambda:[T2.start()])
more_results.place(x=350, y=760)

def close_window():
    print('You clicked the Exit button')
    sys.exit("Closing window")

if __name__ == '__main__':
    check_Root()
    check_API()
    api = shodan.Shodan(str(api_key))
    root.protocol("WM_DELETE_WINDOW", close_window)
    root.resizable(False, False)
    root.mainloop()

import shodan, nmap3, tkintermapview, customtkinter, threading, time, os
from tkinter import IntVar, Checkbutton, Button, Label, Frame, Scrollbar
from tkinter import messagebox, simpledialog
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter.ttk import *
from tkinter import *
import json, logging

def check_API():
    global api_key
    if os.path.exists('.env'):
        secrets = dotenv_values('.env')
        api_key = str(secrets['API_KEY'])
    else:
        dialog = simpledialog.askstring('Input', 'Enter Shodan API key:')
        with open('.env', 'w') as f:
            f.write('API_KEY=' + str(dialog))
            f.close()
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
        Panel1_CVE = LabelFrame(pd_windows, relief='flat', text='CVE Information', background='white')
        Panel2_DNS = LabelFrame(pd_windows, relief='flat', text='DNS Information', background='white')
        
        # FRame windows extension
        pd_windows.add(Panel1_CVE, weight=50)
        pd_windows.add(Panel2_DNS, weight=50)
        pd_windows.pack(fill='both', expand=True)

        self.resizable(False, False)

    def dns_info(self, IP):
        pass

    def cve_info(self, IP):
        pass
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

        # OS detection scan
        C1 = Button(self, text='OS Detection', command=lambda: [self.os_detec(str(self.IP))])
        C1.place(x=50, y=550)
        
        # Dns bruteforce
        C2 = Button(self, text='DNS bruteforce', command=lambda: [self.dns_brute()])
        C2.place(x=50, y=590)
        
        # UDP scan button [Replacing UDP with version detection scan]
        C3 = Button(self, text="Version detection", command=lambda: [self.version_detc(str(IP))])
        C3.place(x=200, y=550)
        
        # Save results checkbox
        self.check_Var = customtkinter.StringVar(value="off") # This will determine if it's been checked.
        C4 = customtkinter.CTkCheckBox(self, text="Save Results", command=lambda: [self.checkbox_event()], variable=self.check_Var, onvalue="on", offvalue="off")
        C4.place(x=200, y=590)

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

            json_object = json.dumps(results[str(IP)]['ports'], indent=4)
            with open(str(IP) + 'VERSION_DETECTION.json', 'w') as f:
                print("Writing to file")
                f.write(json_object)
                f.close()
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
            for data in results[str(IP)]["osmatch"]:
                print('Outputting to screen')
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
                self.text_label.config(text=output)

            json_object = json.dumps(results[str(IP)]["osmatch"], indent=4)
            with open(str(IP) + 'OS_DETECTION.json', 'w') as f:
                f.write(json_object)
                print('Done saving to file')
                f.close()
        elif self.check_Var.get() == 'off':
            print('Normal scan without file saving')
            output = ""
            for data in results[str(IP)]["osmatch"]:
                print('Outputting to screen')
                output += data["name"] + ' ' + 'Accuracy:' + data["accuracy"] + '%' + '\n'
                self.text_label.config(text=output)
    
    def dns_brute(self):
        # DNS bruteforce will have a pop up box prompting for the website name
        target = simpledialog.askstring('Hostname', 'Enter website name:')
        nmap = nmap3.Nmap()
        results = nmap.nmap_dns_brute_script(target)
        if self.check_Var.get() == 'on':
            logging.warning('printing to screen')
            output = ""
            for data in results[0:10]:
                output += data['hostname'] + '\n'
                self.text_label.config(text=output)
            logging.warning('Saving json to file')
            json_object = json.dumps(results, indent=4)
            with open(str(target) + 'DNS.json', 'w') as f:
                logging.warning('Writing json to file')
                f.write(json_object)
                f.close()
        elif self.check_Var() == 'off':
            logging.warning('Normal scan without saving to file')
            output = ""
            for data in results[0:10]:
                output += data['hostname'] + '\n'
                self.text_label.config(text=output)

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
    P2 = moreInfo(IP_Entry.get())
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


# Uncomment this code for program to work normally.
check_API()
api = shodan.Shodan(str(api_key))
root.resizable(False, False)
root.mainloop()

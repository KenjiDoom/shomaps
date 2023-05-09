import tkintermapview, customtkinter
import shodan, nmap3, subprocess, json, time, re, os
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter import messagebox, simpledialog
import threading
from tkinter.ttk import *
from tkinter import *


global api_data
api_data = ''

class Shomap(customtkinter.CTk):
    def __init__(self): # Is this what they mean??? it's a bad idea to run mainloop() function within this function
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")
        fpack = ("MS Serif", 20)

        pw_windows = Panedwindow(self, orient='horizontal')
        self.Panel1_results = LabelFrame(pw_windows, font=fpack, relief='flat', text="General Information", background='white')
        self.panel2_maps = LabelFrame(pw_windows, font=fpack, text="Map", relief='flat', background='white')
        
        pw_windows.add(self.Panel1_results, weight=50)
        pw_windows.add(self.panel2_maps, weight=50)
        pw_windows.pack(fill='both', expand=True)
        
        IP_Entry = customtkinter.CTkEntry(master=self, placeholder_text="Enter IP Address", placeholder_text_color=('black'), height=40, width=500)
        IP_Entry.place(x=700, y=775, anchor='center')      
        
        search_button = customtkinter.CTkButton(master=self, fg_color='red', text='Search', command=lambda:[self.loading_bar(str(IP_Entry.get())), self.display_map(str(IP_Entry.get()))])
        search_button.place(x=1050, y=775, anchor='center')

        # Lets try and open the window up here. (PRIOR TO THE NMAP SCAN)
        # Okay new problem this why I gave up yesterday...
        # It's fetching the IP_Entry.get() prior to us even providng an IP.
        # It's also opening the nmamp box without permissions. Auto open
        # If nmap button clicked then then the program starts
        scan_nmap = customtkinter.CTkButton(master=self, text='Perform Nmap Scan', command=lambda: self.start_nmap_program(str(IP_Entry.get())))
        scan_nmap.configure(DISABLED)
        scan_nmap.place(x=150, y=760)

        more_results = customtkinter.CTkButton(master=self.Panel1_results, text='More Information', command=lambda: self.more_data(str(IP_Entry.get())))
        more_results.place(x=300, y=720)

        self.icon_image = PhotoImage(file='assets/shodan-icon.png')
        self.iconphoto(False, self.icon_image)

    def start_nmap_program(self, IP):
        # Multi processing will go in here
        print(IP)
        print("Starting multi-processing hopes this works")
        nmapp = Process(target=self.nmap_scan(IP))
        nmapp.start()
        nmapp.join()

    def loading_bar(self, IP):
        self.progressbar = Progressbar(self, mode="determinate", length=100)
        self.progressbar.place(x=1195, y=765)
        self.progressbar['value'] = 50
        self.update_idletasks()
        time.sleep(1)
        self.p3 = Process(target=self.shodan_search(IP))
        self.p3.start()
        self.progressbar['value'] = 100
        self.update_idletasks()
        time.sleep(1)

    def shodan_search(self, IP):
        try:
            fpack = ("MS Serif", 15)
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

            for index, (a, b, c, d, e, f, g, h) in enumerate(zip(ip, banner, port, city, domains, asn, coordinates, coordinates2)):
                IP_label = customtkinter.CTkLabel(master=self.Panel1_results,font=fpack, text_color='black', text=('IP Address: ' + str(a))).place(x=10, y=20)     
                PORT_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=('Port numbers: ' + str(c))).place(x=10, y=60)
                CITY_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=('City: ' + str(d))).place(x=10, y=100)
                DOMAINS_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=('Domain: ' + str(e))).place(x=10, y=150)
                ASN_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=('ASN: ' + str(f))).place(x=10, y=200)
                COORDINATES_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=('coordinates: ' + str(g))).place(x=10, y=250)
                COORDINATES2_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='black', text=(str(h))).place(x=215, y=250)
        except shodan.exception.APIError:
            print('You must enter your API key')
            messagebox.showwarning('API Issue', message='Invalid API!!!')

    def more_data(self, IP):
        try:
            host = api.host(IP)
            self.banner = []
            for items in host['data']:
                for items in host['data']:
                    self.banner.append(items['data'])
                for index, (a) in enumerate(zip(self.banner)):
                    banner_info = Label(master=self.extra_data, text_color='black', text=(str(a))).place(x=10, y=20)     
                    print(str(a))
        except shodan.exception.APIError:
            print('You must enter your API key')
            messagebox.showwarning('API Issue', message='Invalid API!!!')

        self.extra_data = Toplevel(self, background='white')
        self.extra_data.title('More information ' + IP)
        self.extra_data.geometry('500x500')
        self.extra_data.resizable(False, False)


def check_API():
    global api_data
    if os.path.exists('.env'):
        secrets = dotenv_values('.env')
        api_data = secrets['API_KEY']
    else:
        dialog = simpledialog.askstring("Input", "Enter API Key:")
        API_key = dialog
        with open('.env', 'w') as f:
            f.write('API_KEY=' + API_key)
            f.close()
        secrets = dotenv_values('.env')
        api_data = secrets['API_KEY']

class Nwindow(customtkinter.CTk):
    data = ''
    def __init__(self, data):
        super().__init__()
        self.geometry('600x650')
        self.title('Nmap Window')

        self.data = data
        
        self.scan_button = Button(master=self, text='Start scan', command=lambda:[self.nmap_scanning(str(self.data))])
        self.scan_button.place(y=10, x=10)

    def nmap_scanning(self, data):
        IP = '45.33.49.119'
        print('The fucntion is working....')
        data_output = 'Here is a list of things to say'
        print(data)
        self.label_to_window = customtkinter.CTkLabel(master=self, text='Output:' + data_output)
        self.label_to_window.place(y=50, x=50)
        #nmap = nmap3.Nmap()
        #results = nmap.nmap_version_detection(str(IP))
        #print(results)
        #for data in results[str(IP)]['ports']:
        #    output = data['portid'] + ' ' + data['state'] + ' ' + data['service']['name']
        #    print(data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'])


class checkcalling(customtkinter.CTk):
    # Think of this as a the shodan window
    def __init__(self):
        super().__init__()
        self.geometry('600x600')
        self.title('Shodan Window')

        shodan_scan_button = Button(master=self, text='Start nmap scan', command=self.start_nmap)
        shodan_scan_button.place(x=50, y=50)

    def start_nmap(self):
        print("Starting shdoan scan")
        
        i = 1
        while(i<=20):
            print('Counting to 20: ' + str(i))
            i += 1

def first_window():
    P1 = checkcalling()
    P1.mainloop()

def second_window():
    P3 = Nwindow('Data was given inside the main loop thing')
    P3.mainloop()

t1 = threading.Thread(target=first_window)
t2 = threading.Thread(target=second_window)
t1.start()
t2.start()


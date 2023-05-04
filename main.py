import tkintermapview, customtkinter
import shodan, nmap3, subprocess, json, time, re, os
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter import messagebox, simpledialog
from tkinter.ttk import *
from tkinter import *

global api_data
api_data = ''

class Shomap(customtkinter.CTk):
    def __init__(self):
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

        # This is auto clicked when app starts, why?
        # lambda will prevent the button from auto running
        scan_nmap = customtkinter.CTkButton(master=self, text='Perform Nmap Scan', command=lambda: self.nmap_scan(str(IP_Entry.get())))
        scan_nmap.place(x=150, y=760)

        more_results = customtkinter.CTkButton(master=self.Panel1_results, text='More Information', command=lambda: self.more_data(str(IP_Entry.get())))
        more_results.place(x=300, y=720)

        self.icon_image = PhotoImage(file='assets/shodan-icon.png')
        self.iconphoto(False, self.icon_image)

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
    
    def display_map(self, IP):
        try:
            host = api.host(IP)
            self.coordinates, self.coordinates2 = [],[]
            for items in host['data']:
                self.coordinates.append(items['location']['latitude'])
                self.coordinates2.append(items['location']['longitude'])
                print(self.coordinates, self.coordinates2)
            for index, (a, b) in enumerate(zip(self.coordinates, self.coordinates2)):
                self.map_widget = tkintermapview.TkinterMapView(self.panel2_maps, corner_radius=0)
                self.map_widget.set_position(a, b)
                self.map_widget.set_marker(a, b, text=str(IP)) # Using google servers
                self.map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=s&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)
                self.map_widget.grid(row=0, column=0, sticky="nsew") 
    
                self.panel2_maps.grid_rowconfigure(0, weight=1)
                self.panel2_maps.grid_columnconfigure(0, weight=1)
        except shodan.exception.APIError:
            print('You must enter your API key')
            messagebox.showwarning('API Issue', message='Invalid API!!!')

    def nmap_scan(self, IP):
        def start_scan(IP):
            print('Starting scan...')
            self.progressbar2['value'] = 50
            self.update_idletasks()
            time.sleep(1)
            nmap = nmap3.Nmap()
            # Nmap returns in json
            results = nmap.nmap_version_detection(str(IP))
            print(results)
            self.progressbar2['value'] = 100
            self.update_idletasks()
            time.sleep(1)
            # Grepping data 
            for data in results[str(IP)]['ports']:
                # This would be the output for ports and services scan
                output = data['portid'] + ' ' + data['state'] + ' ' + data['service']['name']
                print(data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'])
                customtkinter.CTkLabel(master=self.nmap_window, text=output).place(x=100, y=50)

        self.nmap_window = Toplevel(self, background='white')
        self.nmap_window.title("Nmap Scan")
        self.nmap_window.geometry('600x650')

        # Scrollable frame
        frame = customtkinter.CTkScrollableFrame(master=self.nmap_window, width=500, height=500, fg_color='DarkGray', label_text='Scan results for ' + str(IP))
        frame.place(x=50, y=10)
        
        # Porgress bar
        self.progressbar2 = Progressbar(self.nmap_window, mode="determinate", length=100)
        self.progressbar2.place(x=490, y=600)
        
        # What if we broke it down into two subsections... if the 4 way don't work
        customtkinter.CTkCheckBox(self.nmap_window, text='OS Dection').place(x=50, y=580)
        customtkinter.CTkCheckBox(self.nmap_window, text='Stealth Scan').place(x=50, y=610)
        customtkinter.CTkCheckBox(self.nmap_window, text='UDP Scan').place(x=200, y=580)
        customtkinter.CTkCheckBox(self.nmap_window, text='Save Results').place(x=200, y=610)

        nmap_button = customtkinter.CTkButton(self.nmap_window, text_color='black', text='Start Scan', height=55, width=55, hover_color='red', command=lambda: start_scan(str(IP)))
        nmap_button.place(x=370, y=580)
        
        self.nmap_window.resizable(False, False)

    def more_data(self, IP):
        print(IP)

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

if __name__ == '__main__':
    check_API()
    api = shodan.Shodan(str(api_data))
    app = Shomap()
    app.configure(fg_color='grey')
    app.resizable(False, False)
    app.mainloop()

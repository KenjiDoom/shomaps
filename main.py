import tkintermapview, customtkinter, shodan, nmap3, emojis
from tkinter.ttk import *
from tkinter import *

api = shodan.Shodan('')

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
                    
        search_button = customtkinter.CTkButton(master=self, fg_color='red', text='Search', command=lambda:[self.shodan_search(str(IP_Entry.get())), self.display_map(IP_Entry.get())])
        search_button.place(x=1050, y=775, anchor='center')

        # This is auto clicked when app starts, why?
        nmap_scan = customtkinter.CTkButton(master=self.Panel1_results, text='Perform Nmap Scan', command=self.nmap_scan('45.33.49.119'))
        nmap_scan.place(x=150, y=720)

        # More results will open a window with complete shodan information about the target
        more_results = customtkinter.CTkButton(master=self.Panel1_results, text='More Information', command=self.more_data('IP_HERE'))
        more_results.place(x=300, y=720)

        self.icon_image = PhotoImage(file='assets/shodan-icon.png')
        self.iconphoto(False, self.icon_image)

    def shodan_search(self, IP):
        fpack = ("MS Serif", 20)
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
            IP_label = customtkinter.CTkLabel(master=self.Panel1_results,font=fpack, text_color='white', text=('IP Address: ' + str(a))).place(x=10, y=20)     
            PORT_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=('Port numbers: ' + str(c))).place(x=10, y=60)
            CITY_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=('City: ' + str(d))).place(x=10, y=100)
            DOMAINS_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=('Domain: ' + str(e))).place(x=10, y=150)
            ASN_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=('ASN: ' + str(f))).place(x=10, y=200)
            COORDINATES_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=('coordinates: ' + str(g))).place(x=10, y=250)
            COORDINATES2_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text_color='white', text=(str(h))).place(x=215, y=250)
            BANNER_label = customtkinter.CTkLabel(master=self.Panel1_results, font=fpack, text=(str(b))).place(x=10, y=350)

    def display_map(self, IP):
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

    def nmap_scan(self, IP):
        def start_scan():
            nmap = nmap3.Nmap()
            results = nmap.scan_top_ports(str(IP))
            print(results)

        self.nmap_window = Toplevel(self, background='white')
        self.nmap_window.title("Nmap Scan")
        self.nmap_window.geometry('600x600')
        customtkinter.CTkLabel(master=self.nmap_window, text_color='Black', text='Scan Results here').pack()
        customtkinter.CTkCheckBox(self.nmap_window, text='OS Dection').pack()
        customtkinter.CTkCheckBox(self.nmap_window, text='Save Results').pack()
        customtkinter.CTkCheckBox(self.nmap_window, text='Stealth Scan').pack()
        customtkinter.CTkCheckBox(self.nmap_window, text='UDP Scan').pack()
        customtkinter.CTkCheckBox(self.nmap_window, text='Top ports').pack()
        customtkinter.CTkButton(self.nmap_window, text_color='black', text='Scan', command=start_scan())
        self.nmap_window.resizable(False, False)


    def more_data(self, IP):
        print(IP)

app = Shomap()
app.configure(fg_color='grey')
app.resizable(False, False)
app.mainloop()

from tkinter.ttk import *
from tkinter import *
import customtkinter
import tkintermapview
import shodan

api = shodan.Shodan('')


class Shomap(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")

        pw_windows = Panedwindow(self, orient='horizontal')
        self.Panel1_results = LabelFrame(pw_windows, text="General Information")
        self.panel2_maps = LabelFrame(pw_windows, text="Shodan Maps", relief='solid', borderwidth=1)
        
        pw_windows.add(self.Panel1_results, weight=50)
        pw_windows.add(self.panel2_maps, weight=50)
        pw_windows.pack(fill='both', expand=True)
        
        IP_Entry = customtkinter.CTkEntry(master=self, placeholder_text="Enter IP Address", placeholder_text_color=('black'), height=40, width=900)
        IP_Entry.place(x=700, y=775, anchor='center')
        search_button = customtkinter.CTkButton(master=self, text='Search', command=lambda:[self.shodan_search(str(IP_Entry.get())), self.display_map(IP_Entry.get())]).place(x=1250, y=775, anchor='center') 
        
        self.icon_image = PhotoImage(file='/home/kenji/Documents/shomaps/assets/shodan-icon.png')
        self.iconphoto(False, self.icon_image)
    
    def shodan_search(self, IP):
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
            IP_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(a))).place(x=10, y=20)
            BANNER_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(b))).place(x=10, y=50)
            PORT_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(c))).place(x=10, y=150)
            CITY_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(d))).place(x=10, y=200)
            DOMAINS_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(e))).place(x=10, y=250)
            ASN_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(f))).place(x=10, y=300)
            COORDINATES_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(g))).place(x=10, y=350)
            COORDINATES2_label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(h))).place(x=70, y=350)

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
            self.map_widget.set_marker(a, b, text=str(IP))
            self.map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=s&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)
            self.map_widget.grid(row=0, column=0, sticky="nsew") 

            self.panel2_maps.grid_rowconfigure(0, weight=1)
            self.panel2_maps.grid_columnconfigure(0, weight=1)

app = Shomap()
app.configure(fg_color='grey')
app.resizable(False, False)
app.mainloop()

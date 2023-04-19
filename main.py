import customtkinter
import tkintermapview
from tkinter import *
from tkinter.ttk import *
import shodan
# Add your key here
api = shodan.Shodan('')


class Shomap(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")

        pw_windows = Panedwindow(self, orient='horizontal')
        self.Panel1_results = LabelFrame(pw_windows, text="Shodan Results", height=750)
        self.panel2_maps = LabelFrame(pw_windows, text="Shodan Maps")
        pw_windows.add(self.Panel1_results, weight=50)
        pw_windows.add(self.panel2_maps, weight=50)
        pw_windows.pack(fill='both', expand=True)

        # Entry box needed
        IP_Entry = customtkinter.CTkEntry(master=self, placeholder_text="Enter IP Address",placeholder_text_color=('black'), height=40, width=900).place(x=700, y=775, anchor='center')
        search_button = customtkinter.CTkButton(master=self, text='Search', command=self.shodan_search).place(x=1250, y=775, anchor='center') # Don't forget add the command
        
        map_wdiget = tkintermapview.TkinterMapView(self.panel2_maps, width=200, height=200, corner_radius=10)
        map_wdiget.pack()
    
    def shodan_search(self):
        # IP fixed for now
        IP = ''
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
            label = customtkinter.CTkLabel(master=self.Panel1_results, text=(str(a), str(b), str(c), str(d), str(e), str(f), str(g), str(h)))
            label.pack()

    def shodan_map(self):
        map_wdiget = tkintermapview.TkinterMapView(self.panel2_maps, width=10, height=10, corner_radius=0)
        map_wdiget.pack()

app = Shomap()
app.configure(fg_color='grey')
app.resizable(False, False)
app.mainloop()
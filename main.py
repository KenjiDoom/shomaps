import shodan, nmap3, tkintermapview, customtkinter, threading, time, os
from tkinter import messagebox, simpledialog
from multiprocessing import Process
from dotenv import dotenv_values
from tkinter.ttk import *
from tkinter import *

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

# ------------------ Namp window ----------------- #
class Nwindow(customtkinter.CTk):
    IP = ''
    def __init__(self, IP):
        super().__init__()
        self.geometry('600x650')
        self.title('Nmap Window')

        self.IP = IP
        
        self.scan_button = Button(master=self, text='Start scan', command=lambda:[self.nmap_scanning(str(self.IP))])
        self.scan_button.place(x=370, y=565)
        
        self.frame = Frame(master=self, width=500, height=500, background='white')
        self.frame.place(x=50, y=10)
        
        self.scroll = Scrollbar(self.frame)
        self.scroll.place(x=470, y=10, height=485, width=20)

        self.text_label = Label(master=self.frame, width=50, text='Empty').place(x=50, y=50)
        
        self.var1 = IntVar()
        self.var2 = IntVar()
        self.var3 = IntVar()
        self.var4 = IntVar()
        
        C1 = Checkbutton(self, text='OS Detection', onvalue=1, offvalue=0, variable=self.var1, command=self.check_boxes)
        C1.place(x=50, y=550)
        
        C2 = Checkbutton(self, text='Stealth Scan', onvalue=1, offvalue=0, variable=self.var2, command=self.check_boxes)
        C2.place(x=50, y=590)
        
        C3 = Checkbutton(self, text="UDP Scan", onvalue=1, offvalue=0, variable=self.var3, command=self.check_boxes)
        C3.place(x=200, y=550)
        
        C4 = Checkbutton(self, text="Save Results", onvalue=1, offvalue=0, variable=self.var4, command=self.check_boxes)
        C4.place(x=200, y=590)

        self.resizable(False, False)

    def check_boxes(self):
        if self.var1.get() == 1 and self.var2.get() == 0:
            print('You chose OS detection') 
            self.text_label.config(text='You chose OS detection')
        elif self.var1.get() == 0 and self.var2.get() == 1:
            print('You chose stealth scan')
            self.text_label.config(text='You chose stealth scan')
        elif self.var3.get() == 1 and self.var4.get() == 0:
            print('You chose UDP scan')
            self.text_label.config(text='You chose UDP scan')
        elif self.var3.get() == 0 and self.var4.get() == 1:
            print('You chose Save results')
            self.text_label.config(text='You chose to save the results')

    def save_nmap_scan(self, IP, nmap_results):
        print('Writing to file...')
        print(nmap_results)
        print(IP)
        with open(str(IP), 'w') as f:
            f.write(nmap_results)
            f.close()

    def nmap_scanning(self, IP):
        # Identifying service version
        # LEFT OFF HERE FIX THIS WINDOW
        print('The fucntion is working....')
        data_output = 'Here is a list of things to say'
        self.label_to_window = customtkinter.CTkLabel(master=self, text='Output:' + data_output)
        self.label_to_window.place(y=50, x=50)
        nmap = nmap3.Nmap()
        results = nmap.nmap_version_detection(str(IP))
        print(results)
        for data in results[str(IP)]['ports']:
            output = data['portid'] + ' ' + data['state'] + ' ' + data['service']['name']
            print(data['portid'] + ' ' + data['state'] + ' ' + data['service']['name'])

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
T1 = threading.Thread(target=nmap_window)
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

more_results = Button(master=root, text='More Information')
more_results.place(x=350, y=760)

# Uncomment this code for program to work normally.
# check_API()
# api = shodan.Shodan(str(api_key))
root.mainloop()
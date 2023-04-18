import customtkinter
from tkinter import *
from tkinter.ttk import *

class Shomap(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")

        pw_windows = Panedwindow(self, orient='horizontal')
        Panel1_results = LabelFrame(pw_windows, text="Shodan Results", height=750)
        panel2_maps = LabelFrame(pw_windows, text="Shodan Maps")
        pw_windows.add(Panel1_results, weight=50)
        pw_windows.add(panel2_maps, weight=50)
        pw_windows.pack(fill='both', expand=False)

        # Entry box needed
        IP_Entry = customtkinter.CTkEntry(master=self, placeholder_text="Enter IP Address",placeholder_text_color=('black'), height=40, width=1000).place(x=700, y=775, anchor='center')


app = Shomap()
app.configure(fg_color='grey')
app.resizable(False, False)
app.mainloop()
import customtkinter
from tkinter import *
from tkinter.ttk import *

class Shomap(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")

        pw_windows = Panedwindow(self, orient='horizontal')
        Panel1_results = LabelFrame(pw_windows, text="Shodan Results")
        panel2_maps = LabelFrame(pw_windows, text="Shodan Maps")
        pw_windows.add(Panel1_results, weight=50)
        pw_windows.add(panel2_maps, weight=50)
        pw_windows.pack(fill='both', expand=True)


app = Shomap()
app.configure(fg_color='black')
app.resizable(False, False)
app.mainloop()
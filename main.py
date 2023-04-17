import customtkinter

class Shomap(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1400x800")
        self.title("Shomaps")


app = Shomap()
app.configure(fg_color='grey')
app.resizable(False, False)
app.mainloop()
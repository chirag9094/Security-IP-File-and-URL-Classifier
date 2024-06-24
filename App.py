import tkinter as tk
import customtkinter
import configparser
from CTkMessagebox import CTkMessagebox
import URLTab
import FileTab
import IPTab

import VTClient

config = configparser.ConfigParser()
config.read('config.ini')

class App:
    def __init__(self):
        
        self.root = customtkinter.CTk()        
        self.root.title("Infectious program detector")
        self.root.geometry(f"{1920}x{1080}")
        
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.virusTotalAPIkey = config['VirusTotal']['apiKey']
        self.vtClient = VTClient.VTClient(self.virusTotalAPIkey)
        
        # self.menuBar = customtkinter.CTkOptionMenu()
        # self.root.config(menu=self.menuBar)
        # self.fileMenu = customtkinter.CTkOptionMenu(self.menuBar, tearoff=0)
        # self.fileMenu.add_command(label="New")
        # self.fileMenu.add_separator()
        # self.menuBar.add_cascade(label="File", menu=self.fileMenu)

        if not self.vtClient.is_API_key_valid():
            CTkMessagebox('Error', "API key is not valid! Check your config file", icon="warning")

        def _quit():
            self.root.quit()  # The app  will exist when this function is called
            self.root.destroy()
            exit()

        # self.fileMenu.add_command(label="Exit", command=_quit)  # command callback
        self.tabview = customtkinter.CTkTabview(self.root, width=1500, height = 300)
        self.tabview.grid(row=0, column=0, padx=(20, 0), pady=(20, 0), sticky="W")
        self.tabview.add("URL Detection")
        self.tabview.add("IP Detection")
        self.tabview.add("File Detection")
        self.tabview.tab("URL Detection").grid_columnconfigure(0, weight=1)  # configure grid of individual tabs
        self.tabview.tab("IP Detection").grid_columnconfigure(0, weight=1)        

        self.urlFrame = self.tabview.tab("URL Detection")
        URLTab.URLTab(self.root, self.urlFrame, self.vtClient)
        
        self.ipFrame = self.tabview.tab("IP Detection")
        IPTab.IPTab(self.root, self.ipFrame, self.vtClient)
        
        self.fileFrame = self.tabview.tab("File Detection")
        FileTab.FileTab(self.root, self.fileFrame, self.vtClient)        
        
        # self.optionmenu_1 = customtkinter.CTkOptionMenu(self.tabview.tab("URL Detection"), dynamic_resizing=False,
        #                                                 values=["Value 1", "Value 2", "Value Long Long Long"])
        # self.optionmenu_1.grid(row=0, column=0, padx=20, pady=(20, 10))
        # self.combobox_1 = customtkinter.CTkComboBox(self.tabview.tab("URL Detection"),
        #                                             values=["Value 1", "Value 2", "Value Long....."])
        # self.combobox_1.grid(row=1, column=0, padx=20, pady=(10, 10))

        # self.ipFrame = ttk.Frame(self.tabControl)
        # self.ipTab = IPReportTab.IPreportTab(self.tabControl, self.ipFrame, self.vtClient)
        # self.tabControl.add(self.ipFrame, text='IP')

        # self.fileFrame = ttk.Frame(self.tabControl)
        # self.fileTab = FileReportTab.FileReportTab(self.tabControl, self.fileFrame, self.vtClient)
        # self.tabControl.add(self.fileFrame, text='File')

        # self.tabControl.pack(expand=1, fill="both")  # Pack to make visible
    
    def start(self):
        self.root.mainloop()   
        
        
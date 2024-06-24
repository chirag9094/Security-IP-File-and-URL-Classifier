# -*- coding: utf-8 -*-
"""This tab is in charge of sending sending URLs for investigation

VirusTotal gives us the ability to send a suspicious URL to for analysis.
It then returns the results as can be seen inside the code.
"""

from tkinter import ttk
from tkinter import StringVar
import customtkinter
import webbrowser
import pprint
import json

class URLTab:
    def __init__(self, root, frame, vtClient):           
        super().__init__()  
        self.root = root
        self.frame = frame
        self.notificationFrame = 0
        self.c = 1
        
        self.frame.grid_columnconfigure(0, weight=2)
        self.frame.grid_columnconfigure(1, weight=4)   
        self.frame.grid_columnconfigure(2, weight=3)         
        
        customtkinter.CTkLabel(self.frame, text="URL:").grid(column=0, row=0, sticky='E', pady=20)  # What does sticky does?      Sticky sayes where to stick the label to : N,S,E,W
        urlEntry = customtkinter.CTkEntry(self.frame, width=800)        
        urlEntry.grid(column=1, row=0, sticky='W', padx = 30)
        
        customtkinter.CTkLabel(self.frame, text="Malicious Indications:").grid(column=0, row=1, sticky='E')  # <== right-align
        Positive = customtkinter.StringVar()
        PositiveEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=Positive, state='readonly')
        PositiveEntry.grid(column=1, row=1, sticky='W', padx=30)
        
        customtkinter.CTkLabel(self.frame, text="Detections:").grid(column=0, row=2, sticky='E', pady=20)  # <== right-align
        detections = customtkinter.StringVar()
        detectionsEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=detections, state='readonly')
        detectionsEntry.grid(column=1, row=2, sticky='W', padx=30) 
        
        def OpenURL():
            url = "http://127.0.0.1:5000/"
            chrome_path = 'C:/Program Files/Google/Chrome/Application/chrome.exe %s'
            webbrowser.get(chrome_path).open(url)
        
        def MoreDetails():
            self.detailframe = customtkinter.CTkFrame(self.root, width=1300, height=300)
        # using the tkinter grid layout manager
            self.detailframe.grid(column=0, row=2, padx=(20, 0), pady=(20, 0), sticky="NSEW")
            self.detailframe.grid_columnconfigure(1, weight=9)
            MoreDetailsButton = customtkinter.CTkButton(self.detailframe, text='MORE DETAILS', command=OpenURL).grid(column=1, row=0, stick='NSEW')
                             
        def MakeURLError(msg):
            Error = customtkinter.StringVar()
            Error.set(msg)
            self.notificationFrame = customtkinter.CTkFrame(self.root, width=1300, height=300)
        # using the tkinter grid layout manager
            self.notificationFrame.grid(column=0, row=1, padx=(20, 0), pady=(20, 0), sticky="NSEW")
        
            customtkinter.CTkLabel(self.notificationFrame, text="Errors:").grid(column=0, row=0, sticky='E', pady=20, padx=50)
            ErrorEntry = customtkinter.CTkEntry(self.notificationFrame, width=1300, textvariable=Error, state='readonly')
            ErrorEntry.grid(column=1, row=0, sticky='W', padx=30)    
            
        def ModifyJSON(response, maliciousness):
            with open("C:/Users/Chirag C/vit/docs/flask-black-dashboard-master/apps/static/assets/demo/output.json", "w") as outfile:
                response['class'] = self.c
                response['Maliciousness'] = maliciousness
                print(response)
                json.dump(response, outfile)
        
        def _cleanErrorMessage():  # We could have been doing this without a function, but it is more neat that way
            Positive.set("")
            detections.set("")            
            if (self.notificationFrame != 0):
                self.notificationFrame.destroy()
        
        def _getReport():
            # the _ notation before a function means that this function is internal to the class only. As python cannot really prevent you from using it outside the class (as C# for example) the notation is being used to warn other developers not to call this function outside the class
            try:
                _cleanErrorMessage()  # Starting with cleaning the error message bar
                if not urlEntry.get():
                    print('Please enter a URL')
                    MakeURLError(msg = "Please enter a URL!")
                    return

                urlToCheck = urlEntry.get()
                response = vtClient.get_url_report(urlToCheck)                                            
                MoreDetails()
                # pprint.pprint(response)
                Positive.set(response["positives"])
                scans = response["scans"]

                findings = set()
                positive_res = 0
                negative_res = 0
                for key, value in scans.items():
                    if value["detected"]:
                        positive_res += 1
                        findings.add(value["result"])
                    else:
                        negative_res += 1
                # print(positive_res)
                # print(negative_res)
                maliciousness = 0
                if (positive_res >= 0 and positive_res < 3):
                    maliciousness = 1
                elif (positive_res > 3 and positive_res < 6):
                    maliciousness = 2
                else :
                    maliciousness = 3                
                ModifyJSON(response, maliciousness)   
                if (positive_res<1):
                    detections.set("Safe site")
                else:
                    detections.set("Malicious site")

            except Exception as e:
                print(e)

        checkURLinVTButton = customtkinter.CTkButton(self.frame, text='Check in VT!', command=_getReport).grid(column=2, row=0, stick='W', padx=30)
        
           
        
        
        # self.optionmenu_1 = customtkinter.CTkOptionMenu(frame, dynamic_resizing=False,
        #                                                 values=["Value 1", "Value 2", "Value Long Long Long"])
        # self.optionmenu_1.grid(row=0, column=0, padx=20, pady=(20, 10))
        # self.combobox_1 = customtkinter.CTkComboBox(frame,
        #                                             values=["Value 1", "Value 2", "Value Long....."])
        # self.combobox_1.grid(row=1, column=0, padx=20, pady=(10, 10))
        
         

        # using the tkinter grid layout manager
        # self.mainVTURLframe.grid(column=0, row=0, padx=8, pady=4)
        # ttk.Label(self.mainVTURLframe, text="URL:").grid(column=0, row=0, sticky='W')  # What does sticky does?      Sticky sayes where to stick the label to : N,S,E,W
        # urlEntry = ttk.Entry(self.mainVTURLframe, width=Consts.ENTRY_WIDTH)
        # urlEntry.grid(column=1, row=0, sticky='E')

        # ttk.Label(self.mainVTURLframe, text="Positive Indications:").grid(column=0, row=1, sticky='W')  # <== right-align
        # Positive = StringVar()
        # PositiveEntry = ttk.Entry(self.mainVTURLframe, width=Consts.ENTRY_WIDTH, textvariable=Positive, state='readonly')
        # PositiveEntry.grid(column=1, row=1, sticky='W')

        # ttk.Label(self.mainVTURLframe, text="Detections:").grid(column=0, row=2, sticky='W')  # <== right-align
        # detections = StringVar()
        # detectionsEntry = ttk.Entry(self.mainVTURLframe, width=Consts.ENTRY_WIDTH, textvariable=detections, state='readonly')
        # detectionsEntry.grid(column=1, row=2, sticky='W')

        # self.notificationFrame = ttk.LabelFrame(self.frame, text=' Notifications', width=40)
        # # using the tkinter grid layout manager
        # self.notificationFrame.grid(column=0, row=1, padx=8, pady=10, sticky='W')

        # ttk.Label(self.notificationFrame, text="Errors:").grid(column=0, row=0, sticky='W')  # <== increment row for each
        # Error = StringVar()
        # ErrorEntry = ttk.Entry(self.notificationFrame, width=Consts.ENTRY_WIDTH, textvariable=Error, state='readonly')

        # ErrorEntry.grid(column=1, row=0, sticky='W')

        # def _cleanErrorMessage():  # We could have been doing this without a function, but it is more neat that way
        #     Error.set("")

        # def _getReport():
        #     # the _ notation before a function means that this function is internal to the class only. As python cannot really prevent you from using it outside the class (as C# for example) the notation is being used to warn other developers not to call this function outside the class
        #     try:
        #         _cleanErrorMessage()  # Starting with cleaning the error message bar
        #         if not urlEntry.get():
        #             print('Please enter a URL')
        #             Error.set("Please enter a URL!")
        #             return

        #         urlToCheck = urlEntry.get()
        #         response = vtClient.get_url_report(urlToCheck)
        #         print(response)
        #         Positive.set(response["positives"])
        #         scans = response["scans"]

        #         findings = set()
        #         for key, value in scans.items():
        #             if value["detected"]:
        #                 findings.add(value["result"])
        #         detections.set(",".join([str(finding) for finding in findings]))

        #     except Exception as e:
        #         print(e)
        #         Error.set(e)

        # checkURLinVTButton = ttk.Button(self.mainVTURLframe, text='Check in VT!', command=_getReport).grid(column=2, row=0)

        # # Instead of setting padding for each UI element, we can just iterate through the children of the main UI object.
        # for child in self.mainVTURLframe.winfo_children():
        #     child.grid_configure(padx=4, pady=2)
        # for child in self.notificationFrame.winfo_children():
        #     child.grid_configure(padx=4, pady=2)

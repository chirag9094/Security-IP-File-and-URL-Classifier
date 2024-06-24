from tkinter import ttk
from tkinter import StringVar
import customtkinter
import webbrowser
import json

class IPTab:
    def __init__(self, root, frame, vtClient):
        super().__init__()  
        self.root = root
        self.frame = frame
        self.notificationFrame = 0
        self.c = 2
        
        self.frame.grid_columnconfigure(0, weight=2)
        self.frame.grid_columnconfigure(1, weight=4)   
        self.frame.grid_columnconfigure(2, weight=3) 
        
        customtkinter.CTkLabel(self.frame, text="IP:").grid(column=0, row=0, sticky='E', pady=20)  # Sticky sayes where to stick the label to : N,S,E,W
        ipEntry = customtkinter.CTkEntry(self.frame, width=800)
        ipEntry.grid(column=1, row=0, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="Country:").grid(column=0, row=1, sticky='E',pady=10)  # <== right-align
        Country = customtkinter.StringVar()
        CountryEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=Country, state='readonly')
        CountryEntry.grid(column=1, row=1, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="Owner:").grid(column=0, row=2, sticky='E',pady=10)  # <== right-align
        Owner = customtkinter.StringVar()
        OwnerEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=Owner, state='readonly')
        OwnerEntry.grid(column=1, row=2, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="Number of detected URLS:").grid(column=0, row=3, sticky='E',pady=10)  # <== right-align
        numberOfDetectedUrls = customtkinter.StringVar()
        numberOfDetectedUrlsEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=numberOfDetectedUrls, state='readonly')
        numberOfDetectedUrlsEntry.grid(column=1, row=3, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="Number of detected malicious files:").grid(column=0, row=4, sticky='E',pady=10)  # <== right-align
        numberOfDownloadedMaliciousFiles = customtkinter.StringVar()
        numberOfDownloadedMaliciousFilesEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=numberOfDownloadedMaliciousFiles, state='readonly')
        numberOfDownloadedMaliciousFilesEntry.grid(column=1, row=4, sticky='W', padx=30)
        
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
        
        def _cleanErrorMessage():  # We could have been doing this without a function, but it is more neat that way
            if (self.notificationFrame != 0):
                self.notificationFrame.destroy()
            MoreDetails()
        
        def ModifyJSON(response, maliciousness):
            with open("C:/Users/Chirag C/vit/docs/flask-black-dashboard-master/apps/static/assets/demo/output.json", "w+") as outfile:
                response['class'] = self.c
                response['Maliciousness'] = maliciousness
                print(response)
                json.dump(response, outfile)

        def _getReport():
            # the _ notation before a function means that this function is internal to the class only. As python cannot really prevent you from using it outside the class (as C# for example) the notation is being used to warn other developers not to call this function outside the class
            try:
                _cleanErrorMessage()  # Starting with cleaning the error message bar
                if not ipEntry.get():
                    errMessage = 'Please enter an IP address'
                    print(errMessage)
                    MakeURLError(msg = "Please enter an IP Address!")
                    return

                ipToCheck = ipEntry.get()
                response = vtClient.get_ip_report(ipToCheck)
                resolutions = response['resolutions']
                print(resolutions)
                print(response)
                maliciousness = 0
                if (len(resolutions) != 0):
                    maliciousness = 1                
                
                ModifyJSON(response, maliciousness) 
                
                Country.set(response["country"])
                Owner.set(response["as_owner"])
                numberOfDetectedUrls.set(len(response["detected_urls"]))  # len helps us count the amount of items inside the list
                numberOfDownloadedMaliciousFiles.set(len(response["detected_downloaded_samples"]))
                
                

            except Exception as e:
                print(e)
        
        checkURLinVTButton = customtkinter.CTkButton(self.frame, text='Check in VT!', command=_getReport).grid(column=2, row=0)
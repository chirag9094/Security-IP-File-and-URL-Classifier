from tkinter import ttk
from tkinter import StringVar
import customtkinter
import webbrowser
import json

class FileTab:
    def __init__(self, root, frame, vtClient):
        super().__init__()  
        self.root = root
        self.frame = frame
        self.vtClient = vtClient
        self.c = 3
        
        self.frame.grid_columnconfigure(0, weight=2)
        self.frame.grid_columnconfigure(1, weight=4)   
        self.frame.grid_columnconfigure(2, weight=3)   
        
        customtkinter.CTkLabel(self.frame, text="Progress:").grid(column=0, row=1, sticky='E', pady=10)  # <== right-align
        self.progressBar = customtkinter.CTkProgressBar(self.frame,orientation='horizontal', mode='determinate',height=20, width=800)
        self.progressBar.set(0)
        self.progressBar.grid(column=1, row=1, padx=30, sticky='W')
        
        chooseFileButton = customtkinter.CTkButton(self.frame, text="Choose File", width=800, command=self._scanFile).grid(column=1, row=0, pady=20) 
    
        customtkinter.CTkLabel(self.frame, text="File path:").grid(column=0, row=2, sticky='E', pady=10)  # <== right-align
        self.filePath = customtkinter.StringVar()
        filePathEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=self.filePath, state='readonly')
        filePathEntry.grid(column=1, row=2, sticky='W', padx=30)
        
        customtkinter.CTkLabel(self.frame, text="Status:").grid(column=0, row=3, sticky='E', pady=10)  # <== right-align
        self.status = customtkinter.StringVar()
        statusEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=self.status, state='readonly')
        statusEntry.grid(column=1, row=3, sticky='W', padx=30)
        
        customtkinter.CTkLabel(self.frame, text="Malicious Indications:").grid(column=0, row=4, sticky='E', pady=10)  # <== right-align
        self.positiveIndications = customtkinter.StringVar()
        positiveIndicationsEntry = customtkinter.CTkEntry(self.frame, width=800, textvariable=self.positiveIndications, state='readonly')
        positiveIndicationsEntry.grid(column=1, row=4, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="SHA1:").grid(column=0, row=5, sticky='E', pady=10)  # <== right-align
        self.sha1 = customtkinter.StringVar()
        sha1Entry = customtkinter.CTkEntry(self.frame, width=800, textvariable=self.sha1, state='readonly')
        sha1Entry.grid(column=1, row=5, sticky='W', padx=30)

        customtkinter.CTkLabel(self.frame, text="SHA256:").grid(column=0, row=6, sticky='E', pady=10)  # <== right-align
        self.sha256 = customtkinter.StringVar()
        sha256Entry = customtkinter.CTkEntry(self.frame, width=800, textvariable=self.sha256, state='readonly')
        sha256Entry.grid(column=1, row=6, sticky='W', padx=30)
        
        self.scanCheckingTimeInterval = 25000
        
    def OpenURL(self):
        url = "http://127.0.0.1:5000/"
        chrome_path = 'C:/Program Files/Google/Chrome/Application/chrome.exe %s'
        webbrowser.get(chrome_path).open(url)
        
    def MoreDetails(self):
        self.detailframe = customtkinter.CTkFrame(self.root, width=1300, height=300)
        # using the tkinter grid layout manager
        self.detailframe.grid(column=0, row=2, padx=(20, 0), pady=(20, 0), sticky="NSEW")
        self.detailframe.grid_columnconfigure(1, weight=9)
        MoreDetailsButton = customtkinter.CTkButton(self.detailframe, text='MORE DETAILS', command=self.OpenURL).grid(column=1, row=0, stick='NSEW')
        
    
    def showResults(self, results):
        try:
            self.sha1.set(results["sha1"])
            self.sha256.set(results["sha256"])
            self.positiveIndications.set(results["positives"])
        except Exception as e:
            print(e)
    
    def ModifyJSON(self, response, maliciousness):
            with open("C:/Users/Chirag C/vit/docs/flask-black-dashboard-master/apps/static/assets/demo/output.json", "w") as outfile:
                response['class'] = self.c
                response['Maliciousness'] = maliciousness
                print(response)
                json.dump(response, outfile)

    def checkStatus(self):
        try:
            self.scanResult = self.vtClient.get_file_report(self.scanID)
            print(self.scanResult)
            if self.scanResult["response_code"] == -2:  # By reading the next line, you can understand what is the meaning of the -2 response ode
                self.status.set("Scanning...")
                self.progressBar.set(self.progressBar.get() + 5)
                self.root.update_idletasks()
                self.frame.after(self.scanCheckingTimeInterval, self.checkStatus)

            else:
                print("Scan has finished")
                self.hasScanFinished = True
                self.showResults(self.scanResult)
                self.status.set("Finished!")
                self.MoreDetails()
                
                scans = self.scanResult["scans"]

                findings = set()
                positive_res = 0
                negative_res = 0
                for key, value in scans.items():
                    if value["detected"]:
                        positive_res += 1
                        findings.add(value["result"])
                    else:
                        negative_res += 1
                maliciousness = 0
                if (positive_res >= 0 and positive_res < 10):
                    maliciousness = 1
                elif (positive_res > 10 and positive_res < 50):
                    maliciousness = 2
                else :
                    maliciousness = 3                
                self.ModifyJSON(self.scanResult, maliciousness)   

                self.progressBar.set(1)
        except Exception as e:
            if "To much API requests" in str(e):
                pass
    
    def _scanFile(self):
        try:
            self.progressBar.set(0)
            filePath = customtkinter.filedialog.askopenfilename(initialdir="/", title="Select file for VT", filetypes=(("EXE files", "*.exe"), ("all files", "*.*")))
            print(filePath)

            if (filePath):  # Only if the user chose a file, we will want to continue the process
                self.filePath.set(filePath)
                self.status.set("Sending file...")
                self.progressBar.set(0.1)

                self.root.update_idletasks()
                self.scanID = self.vtClient.scan_file(filePath)
                self.hasScanFinished = False
                if not self.hasScanFinished:
                    self.scanResult = self.vtClient.get_file_report(self.scanID)
                    # print(self.scanResult)
                    self.checkStatus()
                    # We could have been using time.sleep() or time.wait(), but then our UI would get stuck.
                    # by using after, we are initiating a callback in which does not blocks our event loop

        except Exception as e:
            print(e)
        
        
        
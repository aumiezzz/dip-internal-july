import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import *
import requests
import time
import json
import base64
import os
from threading import Thread
import tkinter.font as tkfont
import re



#the use of fill.tk = BOTH is to allow for the button to fill areas both vertically and horizontally
#the use of expand=True is to allow for the widgets to change size from its initial dimensions
#used it for a lot of my widgets when packing them

def toMainMenu(parent): #redirects to main menu (within App class)
        err = messagebox.askyesno("Main Menu", "Do you want to exit to the main menu?")
        if err:
            parent.main_menu() #parent is the App class (parent is used to continue the existing instance of App)
            
def clearTab(root): #clears all widgets when changing between modes
    for widget in root.winfo_children():
        widget.destroy()
        
def insertText(T, content): #inserts text and updates the textbox to show the most current data 
    T.insert(tk.END,content) 
    T.update_idletasks() #updates the textbox, otherwise it just waits for the whole function (that it was called in) to complete before displaying anything


class App(tk.Tk): 
    def __init__(self): 
        super().__init__() #inherits all the components from the tk.Tk() tkinter class 
        self.main_menu() #calling upon main_menu function to build widgets



    def main_menu(self):
        clearTab(self)
        self.title('KEEP ME SAFE - MAIN MENU') #defining name of window again in case user wants to come back to the main menu from a selected mode, as title changes depending on user's selected mode
        self.geometry('800x600') # dimensions of the window
        button1 = tk.Button(self, width=30,text="WEBSITE SCANNING",command=self.show_websiteScan)
        button1.pack(fill=tk.BOTH,expand=True)
        button2 = tk.Button(self, width=30,text="FILE SCANNING",command=self.show_fileScan)
        button2.pack(fill=tk.BOTH,expand=True)
        button3 = tk.Button(self, width=30,text="SAFETY ADVICE", command=self.show_Advice)
        button3.pack(fill=tk.BOTH,expand=True)

    #the methods below are called upon when their respective button is clicked, it creates an instance of that respective class
    def show_Advice(self): 
        showAdvice(self)

    def show_websiteScan(self):
        websiteScan(self)
    def show_fileScan(self):
        fileScan(self)

class fileScan(tk.Frame): #inherts the root window (as we don't want new windows to pop up for each mode)
    #preset dialogues to show, put here so it's easier to refer back and edit in case there's a need to
    quickScanUploadError = "\n\nTHERE WAS AN ERROR UPLOADING YOUR SELECTED FILE, PERHAPS YOUR TYPE OF FILE IS NOT SUPPORTED IN THIS MODE. TRY USING THE ADVANCED SCAN FEATURE INSTEAD."
    quickScanSizeError = "\n\nYOUR SELECTED FILE EXCEEDED THE SIZE LIMIT. TO UPLOAD THIS FILE, USE THE ADVANCED SCAN OPTION INSTEAD"
    quickScanCleanResult = "\n\nAccording to a quick scan of your file, there were no threats detected on it. If you've downloaded this from a reputable site (such as Microsoft, Adobe etc), you will be fine. However, if you've downloaded this off of a site you're not too familiar with, I recommend that you run the file through the advanced scan as well, this is because malware that hasn't been spread to a lot of computers will not get picked up under the quick scan feature."
    quickScanMaliciousResult = "\n\nAfter an analysis of your file, we've found malicious content within the file that could be harmful for your computer. Do not open this file, instead permanently delete that. If you've already opened this file, then I recommend you use an antivirus software such as MalwareBytes or McAfee to try quarantine and remove the file from your system. If that doesn't work, I recommend that you reset your system back to your computer's last restore point, you can find how to do this on Youtube. Be wary of the files that you download from the internet."
    quickScanGuide = "Select your file by clicking the 'CHOOSE FILE' button above. Once you've selected the file, you may choose between a 'QUICK SCAN' or an 'ADVANCED SCAN' of the file by clicking the respective button on the right-hand side."
    advancedScan_nonMalicious = "\n\nIt's likely that the file you've submitted does not oontain any type of virus and is safe to use. However, some malware that is brand-new and hasn't been seen before is not likely to get picked up as malicious, therefore ensure the authenticity of this file... ensure you've downloaded it directly from the application's page and not frmo a third party to keep yourself safe."
    advancedScan_lilMalicious = "\n\nThe file has been flagged by a few scanners, they may be false-positives (falsley detected as malicious) but treat this file with caution. Ensure you've downloaded it from a reputable website and that it's absolutely necessary to use. For safety, I recommend using this file within a virtual machine so that if the file does contain malware, your actual machine will be safe (as only the virtual machine would be affected)."
    advancedScan_veryMalicious = "\n\nThe file you've submitted has been flagged by multiple scanners, it is likely that this file contains malware. Permanently delete this file from your system, DO NOT OPEN IT. If you'd like to learn more information about malware, you can restart the program and select 'Safety Advice'."

            
    def __init__(self,parent): #initialises instance, clears all existing widgets, sets up frames to prepare for new widgets
        super().__init__(parent) #inherits all methods from App() which is the parent function (as it was called upon via fileScan(self)) where the parent variable is derived from the self, same with other classes  
        clearTab(parent) 
        parent.title("KEEPMESAFE - FILE SCAN")
        parent.geometry('1000x600')
        frame = tk.Frame(parent)
        frame.pack(fill=tk.BOTH,expand=True)
        myFrame = tk.Frame(frame)
        myFrame.pack(side=tk.RIGHT,fill=tk.BOTH,expand=True)
        secFrame = tk.Frame(frame)
        secFrame.pack(side=tk.TOP,pady=(15,0),padx=(10,0))
        self.create_widgets(frame,myFrame,secFrame,parent)
        
    def openFile(self,E): #popup dialog for user to select file
        file = filedialog.askopenfile()
        if file:
              filepath = os.path.abspath(file.name)
              
              E.delete(0,tk.END)
              E.insert(0, f'{filepath}') #inserts the file name into entry box, in case user wants to scan a newly made file under same directory, they can easily tweak it

    
    def create_widgets(self,frame,myFrame,secFrame,parent): #sets up widgets and layout
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        scrollbar = tk.Scrollbar(frame, command=T.yview)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y,padx=(0,15),pady=10 )
        mainMenu_button = tk.Button(myFrame,width=30,text='MAIN MENU',command=lambda:toMainMenu(parent)) 
        quickScan_button = tk.Button(myFrame,width=30,text='QUICK SCAN',command=lambda:self.quickScan(E,T))
        advancedScan_button = tk.Button(myFrame,width=30,text='ADVANCED SCAN',command=lambda:self.advancedScan(E,T))
        E = tk.Entry(secFrame,width=90)
        link_button = tk.Button(secFrame,text='CHOOSE FILE',command=lambda:self.openFile(E))
        link_button.pack(side=tk.LEFT,padx=(12,20))
        E.pack(side=tk.LEFT,padx=(5,32))
        mainMenu_button.pack(side=tk.BOTTOM,pady=10,padx=(5,20))
        quickScan_button.pack(side=tk.TOP,padx=(5,20),pady=(10,0),fill=tk.BOTH,expand=True)
        advancedScan_button.pack(side=tk.TOP,padx=(5,20),fill=tk.BOTH,expand=True)
        current_font = T['font']
        new_font = tkfont.Font(font=current_font)
        new_font.configure(size=13)  # use to change font size, come back to later
        T.configure(font=new_font)
        T.insert(tk.END, self.quickScanGuide)
        T.pack(padx=(20,0),pady=(10,10),fill=tk.BOTH,expand=True)
        T.config(yscrollcommand=scrollbar.set) #configures scroll wheel to work with textbox
        

    def quickScan(self,E,T): #quick scan mode
        file_path = E.get() 
        def scan(): #error prevention and making api calls to cloudmersive for quick scan
            T.delete("1.0", tk.END)
            insertText(T,"QUICK SCANNING...")
            headers = {
                'Apikey': '7d1e1d3f-5240-4ed4-98ef-ef8932a12c42', #authentication key to use the api
            }
            try:
                files = {
                    'inputFile': open(file_path, 'rb'), #checks if the file exists
                }
            except:
                insertText(T,"\n\nINVALID FILE PATH SPECIFIED, PLEASE CHOOSE THE FILE AGAIN") #if file does not exist, this will pop up
                messagebox.showinfo("INVALID FILE","You've inputted an invalid file path, please double-check and try again.")
                return #stops function from continuing further due to error
            try:
                response = requests.post('https://api.cloudmersive.com/virus/scan/file', headers=headers, files=files)
            except:
                #in case of an error uploading the to the cluoudmerisve api
                insertText(T,self.quickScanUploadError)
                
            if 'Input file was larger than the limit' in str(response.content):
                insertText(T,self.quickScanSizeError)
                return
                
            results = json.loads(response.content)
            if results['CleanResult'] == True: #if file is scanned and found to be clean
                insertText(T,self.quickScanCleanResult)
            elif results['CleanResult'] == False: #if file is scanned and found to be malicious
                insertText(T,self.quickScanMaliciousResult)
        t = Thread(target=scan) # this was used to prevent the tkinter tab from not responding when changing onto a different tab (meaning it will remain active in the background)
        t.start()

        
    def advancedScan(self,E,T): #advanced scan mode
        file_path = E.get() #getting file path specified in the entry box, from openfile function
        def scan(): 
            T.delete("1.0", tk.END) #wipes all data in textbox so different scans don't build up on each other
            insertText(T,"UPLOADING FILE TO WEBSERVER FOR ANALYSIS")
            url = "https://www.virustotal.com/api/v3/files"
            try:
                files = {"file": (file_path, open(file_path, 'rb'))} #checks if file exists
            except:
                insertText(T,"\n\nINVALID FILE PATH SPECIFIED, PLEASE CHOOSE THE FILE AGAIN") # if file doesn't exxist
                messagebox.showinfo("INVALID FILE","You've inputted an invalid file path, please double-check and try again.")
                return
            headers = {
            "accept": "application/json",
            "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f" #api key used for authentication w virustotal api
            }
            try:
                response = requests.post(url, files=files, headers=headers) #uploading file 
            except:
                insertText(T,"\n\nTHERE WAS AN ERROR UPLOADING YOUR SELECTED FILE, PERHAPS THE SIZE OF YOUR FILE IS OVER 64MB. PLEASE MAKE USE OF A REPUTABLE ANTI-VIRUS SCANNER SUCH AS MCAFEE TO SCAN THIS FILE.") #in case file is too big
            grr = json.loads(response.text) #formatting response text into json for easy-to-read format
            file_id = grr['data']['id'] # calling upon file id from json response for reference in next API call 
            #analyse file
            url = "https://www.virustotal.com/api/v3/analyses/" + str(file_id) #this api requires file id within url hence why file id is added
            headers = {
            "accept": "application/json",
            "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"
            }
            response = requests.get(url, headers=headers) #api is scanning file
            insertText(T,"\n\nSCANNING FILE")
            getmd5 = json.loads(response.text)
            status = getmd5['data']['attributes']['status']
            start = time.time()
            while status == "queued": #scan is still being completed
                time.sleep(5)
                url = "https://www.virustotal.com/api/v3/analyses/" + str(file_id)
                headers = {
                "accept": "application/json",
                "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"
                }
                response = requests.get(url, headers=headers) #calling upon API to see if scan is still queued
                getmd5 = json.loads(response.text) #converting response string into json to call upon easier
                status = getmd5['data']['attributes']['status']
                try:
                    insertText(T,"\n[+] STILL SCANNING...")
                except Exception as e:
                    status = 'MAIN_MENU' #would stop working if user goes to main menu, hence changing status
            if status == 'MAIN_MENU': #stopping function from continuing as user is in main menu
                return
            md5 = getmd5['meta']['file_info']['md5'] #md5 hash within the json response, used for next api call
            #file report
            url = "https://www.virustotal.com/api/v3/files/" + str(md5) #md5 needed in url for api call hence why string md5 is in url
            headers = {"accept": "application/json", "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"}
            response = requests.get(url, headers=headers)
            file_report = json.loads(response.text) #converting the response string format into json format to easily read and get information
            scan_amount = file_report['data']['attributes']['times_submitted'] #how many times file was scanned on virustotal api
            file_name = file_report['data']['attributes']['meaningful_name'] #name of file user uploaded for scanning
            file_stats = file_report['data']['attributes']['last_analysis_stats'] # compilation of virus scanners' analysis stats, malicious, safe etc
            insertText(T,"\n\nThe file you've uploaded, " + file_name + " has been submitted for scanning " + str(scan_amount) + " times (from you and other people).")
            total_scanner_count = file_stats['malicious'] + file_stats['undetected'] # adding up stats of undetected and malicious results to calculate total amount of virus scanners used 
            insertText(T,"\n\nAccording to our analysis of the file, " + str(file_stats['malicious'])  + " out of " + str(total_scanner_count) + " scanners used have reported the file as malicious.")
            end = time.time()
            time_taken = end - start
            insertText(T,"\n\nTime taken: " + "%.2f" % time_taken + " seconds") #measuring how long it took to scan file
            if file_stats['malicious'] == 0: #giving advice to the user bsaed on how many counts of maliciousness the file has
                insertText(T,self.advancedScan_nonMalicious)
                #insertText(T,"\n\nIt's likely that the file you've submitted does not oontain any type of virus and is safe to use. However, some malware that is brand-new and hasn't been seen before is not likely to get picked up as malicious, therefore ensure the authenticity of this file... ensure you've downloaded it directly from the application's page and not frmo a third party to keep yourself safe.")
            elif file_stats['malicious'] > 0 and file_stats['malicious'] <= 5:
                insertText(T,self.advancedScan_lilMalicious)
                #insertText(T,"\n\nThe file has been flagged by a few scanners, they may be false-positives (falsley detected as malicious) but treat this file with caution. Ensure you've downloaded it from a reputable website and that it's absolutely necessary to use. For safety, I recommend using this file within a virtual machine so that if the file does contain malware, your actual machine will be safe (as only the virtual machine would be affected).") 
            elif file_stats['malicious'] >=6:
                insertText(T,self.advancedScan_veryMalicious)
                #insertText(T,"\n\nThe file you've submitted has been flagged by multiple scanners, it is likely that this file contains malware. Permanently delete this file from your system, DO NOT OPEN IT. If you'd like to learn more information about malware, you can restart the program and select 'Safety Advice'.")
            check_save = messagebox.askyesno("Save File", "Do you want to save this file?") #asks user if they'd like to save report of their scanned file
            if check_save: #if they answer yes
                try:
                    saveName = file_name.replace('.', ' ') 
                    f = open(str(saveName) + ' Report.txt', 'w')
                    saveContent = str(file_report['data']['attributes']['last_analysis_results']).replace('},', '\n') 
                    saveContent = saveContent.replace('{', '')
                    f.write(saveContent)
                    f.close()
                    insertText(T,"\n\nSuccesfully saved the full scan report in the same directory as this program, under the name: " + str(saveName) + " Report.txt\n") 
                    messagebox.showinfo("Report saved","Succesfully saved the full scan report under the name: " + str(saveName) + " Report.txt")
                except:
                    insertText(T,"\n\nThere was an error saving the full scan report, please try again. If the problem persists, perhaps it's a problem with the file itself.")
                    messagebox.showinfo("Error saving report","There was an error saving the full scan report. See the bottom of the textbox for more information.")  
        t = Thread(target=scan) #use of threads to counter prorgam not responding when changing tabs while doing scan
        t.start()
        
class websiteScan(tk.Frame): #inherits the root window from App (so more windows don't pop up each time this class is called)
    #preset dialogues, put them here because it's easier to locate and edit
    websiteScan_lilMalicious = "\n\nAlthough this site has been detected as malicious by only a few scanners, this does not mean that the site is safe. Many malware and phishing pages have antibots (embedded security) within them to try and trick scanners into thinking it's a regular website. So my advice to you is to be wary of this site, do not download anything from it nor enter any of your personal information on there."
    websiteScan_veryMalicious = "\n\nIt is likely that this site is unsafe. Do not download anything from there or enter any of your personal information if prompted (this includes your usernames, passwords, emails, etc.). If you've already done some of the things mentioned, ensure that you change those details to prevent scammers from logging in to your accounts. If you want to read more information about this, you can click the 'Main Menu' button in the bottom right and then navigate to the tab 'Safety Advice'."
    websiteScan_nonMalicious = "\n\nThis site has not been detected as malicous by any virus scanners. It is likely safe to use. However brand new websites are not often picked up as malicious so be careful when entering your personal information and if you feel as if something is off, do some research about the website and determine what to do from there."

    

    def __init__(self,parent): #clears existing widgets, to create a new frame for new widgets
        super().__init__(parent) #inherits the components and methods from the App class (as 'parent')
        clearTab(parent)
        root = parent
        parent.title("KEEPMESAFE - WEBSITE SCAN") #updating title to show appropriate mode
        frame = tk.Frame(root)
        frame.pack(fill=tk.BOTH,expand=True)
        myFrame = tk.Frame(frame)
        myFrame.pack(side=tk.BOTTOM)
        self.create_widgets(frame,myFrame,parent)

    def create_widgets(self,frame,myFrame,parent): #setting up widgets and layout for websiteScan mode 
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        mainMenu_button = tk.Button(myFrame,width=30,text='MAIN MENU',command=lambda:toMainMenu(parent))
        E = tk.Entry(myFrame)
        link_button = tk.Button(myFrame,text='SCAN URL',command=lambda:self.scanURL(E,T))
        link_button.pack(side=tk.LEFT)
        E.pack(side=tk.LEFT,padx=(5,20))
        mainMenu_button.pack(side=tk.LEFT,pady=10)
        T.pack(padx=20,pady=(10,0),fill=tk.BOTH,expand=True)
        current_font = T['font']
        new_font = tkfont.Font(font=current_font)
        new_font.configure(size=13)  # use to change font size, come back to later
        T.configure(font=new_font)
        insertText(T, "Enter the URL of the website you would like to scan in the white-space entry box below, next to the 'SCAN URL' button.")
        
    def scanURL(self,E,T): #scanning function, called upon when 'SCAN URL' button is pressed
        link = E.get()
        T.delete("1.0", tk.END)
        if not '.' in link: #used to detect invalid url, as url contains '.' in them always so this is used to make the user enter a proper url (something.com) instead of somethingcom.
            messagebox.showinfo("Invalid Link", "You entered an invalid link, please double-check your input and try again.")
            return
        if ' ' in link:
            link.replace(' ','')
       
        def remove_slash_in_domain(url): #better error handling detection  of incorrect https:// spelling or typos in URL e.g httssp://google.com turns into google.com, done with the use of regex 
            url = re.sub(r'^([^/]+)/', r'\1', url)
            cleaned_url = re.sub(r'^.*?/', '', url)
            cleaned_url = re.sub(r'\/+(?=\.)', '', cleaned_url)
            return cleaned_url
        link = remove_slash_in_domain(link) #cleaning user-input errors, if any
        link = 'https://' + link #adds https:// to link (this is to account for any typos with https:// the user may have done or if the user did not include https:// at all.
        insertText(T,'SCANNING...')
        url_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=") #used to encode the url into a format that the API can read
        count = 0
        headers = {
        'x-apikey': 'a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f', #used to authenticate my request
        }
        response = requests.get('https://www.virustotal.com/api/v3/urls/' +  url_id, headers=headers) #creating a request to get information about the website 
        data = json.loads(response.content) #converting the content of the response into a json format to be able to read the data more easily
        try:
            stats = data['data']['attributes']['last_analysis_stats']
        except:
            insertText(T, "\n\nWe ran into an issue trying to scan this website, perhaps the website " + str(link) + " doesn't exist? If the website does exist and this problem persits, you can scan this website online with google, simply search for 'scan website google safe browsing' and click on the second link then follow the steps mentioned on there. Feel free to scan another website by pressing the 'Main Menu' button below.")
            return
        
        #printing what category the website falls under according to reports of the website from external sources.
        try:
            insertText(T,  f"\n\nThe website ({data['data']['attributes']['last_final_url']}) is based around: {data['data']['attributes']['categories']['alphaMountain.ai']}.")
        except:
            try:
                if data['data']['attributes']['categories']['alphaMountain.ai'] == 'Unrated':
                   insertText(T, " This may potentially be a new website, be careful.\n") #if category is unrated, may indicate that website is brand new hence my warning
            except:
                pass
            
        #telling user how many scanners the website submitted was detected as malicious by, out of 90 total scanners that are used in VirusTotal api for web scanning.
        T.insert(tk.END, "\n\nAccording to our analysis, the website: " + data['data']['attributes']['last_final_url'] + " is detected as malicious by " + str(stats['malicious']) + ' malware/phishing scanners (out of 90)')
        if stats['malicious'] > 0:
            err = str(data['data']['attributes']['last_analysis_results'])
            malicious_reason = err.count('malicious') - stats['malicious']
            #details the type of malicious activity that's been detected on the website the user hass submitted
            T.insert(tk.END,". Some reasons behind the detections were:\n  " + str(malicious_reason) + " reports of malicious activity.\n  " + str(err.count('phishing')) + " reports of phishing.")

        #prints advice to the user based on how many reports of malicious activity the website had.
        if stats['malicious'] > 0 and stats['malicious'] <= 5:
            insertText(T, self.websiteScan_lilMalicious)
        if stats['malicious'] >= 6:
            insertText(T, self.websiteScan_veryMalicious)
        if stats['malicious'] == 0:
            insertText(T, self.websiteScan_nonMalicious)

class showAdvice(tk.Frame): #inherits root window to prevent additional windows popping up each time the class is called upon
    advicePhishing = "PHISHING TIPS:\nBe cautious with emails. Some emails may ask you to visit links. Check the sender's email address and if you don't recognise it, don't click on anything. If you do recognise it but it seems suspicious to you, verify the authenticity of it by speaking with the supposed sender of the email (in case of an organisation, call their support number as sender email addresses can be spoofed).\n\nEnable two-factor authentication on all your accounts to add an additional layer of security. By doing so, somebody that may have your login information to one of your accounts will not be able to access your accounts unless you provide them with the two-factor code (which in most cases, is received through text message.)\n\nBe cautious of what you share on social media. Overly sharing information may lead to people figuring out some of your personal information/passwords. For example, if you share your birth date with social media and your phone passcode happens to be the year of your birthday... it presents a serious risk to your security hence why it's best not to overly share things on social media.\n\nDon't share your personal information like passwords, credit cards etc over the phone or online (unless you know for certain that the website you're sharing this information with is reputable and can be trusted.\n\nDo not trust unsolicited calls or messages, especially from numbers that are claiming to be a part of an organisation (banks for example. Verify the authenticity of the phone call or text message by calling that particular organisation's (that the number might be posing as support number and ask about the call/message you may have received.)\n\nBe careful with links. When visting a website, ensure that the URL that appears in your browser's address bar matches up with what you think the actual website's URL is as although some websites may look the same, it could be an attempt from scammers trying to phish you for your information.\n\nOne of the best things you could do is to educate yourself about this topic, do some research online about phishing and learn about the common strategies that scammers use to lure victims in so you can identify them and prevent yourself from falling victim as well as be able to pass this information on to others, preventing them from falling victim too."
    adviceMalware = "MALWARE TIPS:\nBe cautious with emails. Ensure that you recognise the sender's email address if it's urging you to download a file. If you don't recognise the sender, do not download the file. On the off chance that you do recognise the sender but the email still seems supicious, you can verify its authenticity by speaking with the supposed sender of the email (in the case of an organisation, call their support number as sender email addresses can be easily spoofed by scammers.)\n\nUpdate your softwares, such as your operating system, browsers etc in order to ensure that the security patches of those softwares are up-to-date as you'll be more protected.\n\nIf you can afford anti-virus software, purchase it. It is well worth the investment as it protects you from malicious files that you may download or that may pop up on your system as well as protecting you online from visiting malicious links, thus keeping your personal information safe and your security being almost impenetrable.\n\nBe cautious when downloading things from the internet. To keep yourself safe, ensure that you're only downloading files from reputable sources and scan all files with an anti-virus software. You could even use this program for scanning your files! :)\n\nMake use of adblockers. By using adblockers, you'll be preventing yourself from potentially experiencing malicious ads when visiting websites.\n\nWith malware, prevention is the best defense. So educate yourself about malware, learn how it works, how it's spread etc. Follow the latest cybersecurity news so that you can prevent yourself from falling victim to malware and you can also pass on the knowledge you learn to family and friends, thus preventing them from falling victim to malware as well and keeping more people safe online."
    
    def __init__(self,parent): #clears existing widgets, sets up new layout and widgets
        super().__init__(parent) #inherits the methods from the App class
        clearTab(parent)
        root = parent
        parent.title("KEEPMESAFE - ADVICE")
        parent.geometry('800x750')
        frame = tk.Frame(root)
        frame.pack(padx=10,fill=tk.BOTH,expand=True)
        self.create_widgets(frame,parent)
        
    def showPhishing(self,T):
        T.delete("1.0", tk.END) 
        T.insert(tk.END, self.advicePhishing)

    def showMalware(self,T):
        T.delete("1.0",tk.END)
        T.insert(tk.END,self.adviceMalware)
   
            

    def create_widgets(self,frame,parent):
        phishing_button = tk.Button(frame, width=30, text='PHISHING', command=lambda: self.showPhishing(T)) #lambda used to prevent command from automatically executing (as T variable is passed to function which automatically executes code)
        malware_button = tk.Button(frame, width=30, text='MALWARE', command=lambda: self.showMalware(T))
        mainMenu_button = tk.Button(frame,width=30,text='MAIN MENU',command=lambda : toMainMenu(parent))
        mainMenu_button.pack(pady=(0,10),padx=10,side=tk.BOTTOM,fill=tk.BOTH,expand=True)
        malware_button.pack(padx=10,side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        phishing_button.pack(padx=10,side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        T.insert(tk.END, f"Select from either the 'PHISHING' or 'MALWARE' button below to display advice and information about the respective category.")
        scrollbar = tk.Scrollbar(frame, command=T.yview)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y,padx=(0,15),pady=10 )
        T.pack(padx=(20,0),pady=(10,10),fill=tk.BOTH,expand=True)
        current_font = T['font']
        new_font = tkfont.Font(font=current_font)
        new_font.configure(size=13)  # use to change font size, come back to later
        T.configure(font=new_font)
        T.config(yscrollcommand=scrollbar.set)



if __name__ == '__main__': # only runs the program if it is the main program (not called upon in another python file as then the __name__ would not be '__main__')
    app = App() 
    app.mainloop()

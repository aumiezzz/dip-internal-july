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



def clearTab(): #clears all widgets when changing between modes
    for widget in root.winfo_children():
        widget.destroy()
        
def insertText(T, content): #inserts text and updates the textbox to show the most current data 
    T.insert(tk.END,content) #inserts text into textbox, used it to make inserting text easier
    T.update_idletasks() #continuously updates the textbox, otherwise it just waits for the whole function to complete before displaying anything
    

class scanFile: # class for scanning file
    quickScanUploadError = "\n\nTHERE WAS AN ERROR UPLOADING YOUR SELECTED FILE, PERHAPS YOUR TYPE OF FILE IS NOT SUPPORTED IN THIS MODE. TRY THE ADVANCED SCAN INSTEAD."
    quickScanSizeError = "\n\nYOUR SELECTED FILE EXCEEDED THE SIZE LIMIT. TO UPLOAD THIS FILE, USE THE ADVANCED SCAN OPTION INSTEAD"
    quickScanCleanResult = "\n\nAccording to a quick scan of your file, there were no threats detected on it. If you've downloaded this from a reputable site (such as Microsoft, Adobe etc), you will be fine. However, if you've downloaded this off of a site you're not too familiar with, I recommend that you run the file through the advanced scan as well, this is because malware that hasn't been spread to a lot of computers will not get picked up under the quick scan feature."
    quickScanMaliciousResult = "\n\nAfter an analysis of your file, we've found malicious content within the file that could be harmful for your computer. Do not open this file, instead permanently delete that. If you've already opened this file, then I recommend you use an antivirus software such as MalwareBytes or McAfee to try and remove the file from your system processes. If that doesn't work, I recommend that you reset your system back to your computer's last restore point, you can find how to do this on Youtube. Be wary of the files that you download from the internet."
    quickScanGuide = "Select your file by clicking the 'CHOOSE FILE' button above. Once you've selected the file, you may choose from a 'QUICK SCAN' or a 'ADVANCED SCAN' of the file by clicking the appropriate button on the right-hand side."
    def openFile(E): #used for retrieving the file 
        file = filedialog.askopenfile()
        if file:
              filepath = os.path.abspath(file.name)
              
              E.delete(0,tk.END)
              E.insert(0, f'{filepath}') #inserts the file name into entry box, in case user wants to scan a newly made file under same directory, they can easily tweak it

    
    def quickScan(E,T): # quick scan mode
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
                return
            try:
                response = requests.post('https://api.cloudmersive.com/virus/scan/file', headers=headers, files=files)
            except:
                #in case of an error uploading the to the cluoudmerisve api
                insertText(T,scanFile.quickScanUploadError)
                
            if 'Input file was larger than the limit' in str(response.content):
                insertText(T,scanFile.quickScanSizeError)
                return
                
            results = json.loads(response.content)
            if results['CleanResult'] == True: #if file is scanned and found to be clean
                insertText(T,scanFile.quickScanCleanResult)
            elif results['CleanResult'] == False: #if file is scanned and found to be malicious
                insertText(T,scanFile.quickScanMaliciousResult)
        t = Thread(target=scan) # this was used to prevent the tkinter tab from not responding when changing onto a different tab (meaning it will remain active in the background)
        t.start()
    def advancedScan(E,T): #advanced scan mode
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
                insertText(T,"\n[+] STILL SCANNING...")



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
                insertText(T,"\n\nIt's likely that the file you've submitted does not oontain any type of virus and is safe to use. However, some malware that is brand-new and hasn't been seen before is not likely to get picked up as malicious, therefore ensure the authenticity of this file... ensure you've downloaded it directly from the application's page and not frmo a third party to keep yourself safe.")
            elif file_stats['malicious'] > 0 and file_stats['malicious'] <= 5:
                insertText(T,"\n\nThe file has been flagged by a few scanners, they may be false-positives (falsley detected as malicious) but treat this file with caution. Ensure you've downloaded it from a reputable website and that it's absolutely necessary to use. For safety, I recommend using this file within a virtual machine so that if the file does contain malware, your actual machine will be safe (as only the virtual machine would be affected).") 
            elif file_stats['malicious'] >=6:
                insertText(T,"\n\nThe file you've submitted has been flagged by multiple scanners, it is likely that this file contains malware. Permanently delete this file from your system, DO NOT OPEN IT. If you'd like to learn more information about malware, you can restart the program and select 'Safety Advice'.")
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

        

    def fileScanSetup(): #layout for file scan mode
        clearTab()
        root.title("KEEPMESAFE - File Scan")
        frame = tk.Frame(root)
        frame.pack(fill=tk.BOTH,expand=True)
        myFrame = tk.Frame(frame)
        myFrame.pack(side=tk.RIGHT,fill=tk.BOTH,expand=True)
        secFrame = tk.Frame(frame)
        secFrame.pack(side=tk.TOP,pady=(15,0),padx=(10,0))
        
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        scrollbar = tk.Scrollbar(frame, command=T.yview)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y,padx=(0,15),pady=10 )
        #retry_button = tk.Button(myFrame,width=30,text='NEW WEBSITE SCAN',command=lambda:scanWebsite.scanURL(T))
        #retry_button.pack(side=tk.LEFT)
        mainMenu_button = tk.Button(myFrame,width=30,text='MAIN MENU',command=SafetyAdvice.toMainMenu)
        quickScan_button = tk.Button(myFrame,width=30,text='QUICK SCAN',command=lambda:scanFile.quickScan(E,T))
        advancedScan_button = tk.Button(myFrame,width=30,text='ADVANCED SCAN',command=lambda:scanFile.advancedScan(E,T))
        E = tk.Entry(secFrame,width=90)
        link_button = tk.Button(secFrame,text='CHOOSE FILE',command=lambda:scanFile.openFile(E))
        link_button.pack(side=tk.LEFT,padx=(12,20))
        E.pack(side=tk.LEFT,padx=(5,32))
        mainMenu_button.pack(side=tk.BOTTOM,pady=10,padx=(5,20))
        quickScan_button.pack(side=tk.TOP,padx=(5,20),pady=(10,0),fill=tk.BOTH,expand=True)
        advancedScan_button.pack(side=tk.TOP,padx=(5,20),fill=tk.BOTH,expand=True)
        
        current_font = T['font']
        new_font = tkfont.Font(font=current_font)
        new_font.configure(size=11)  # use to change font size, come back to later

        T.configure(font=new_font)
        T.insert(tk.END, scanFile.quickScanGuide)



        
        #T.insert(tk.END, 'Select the button that aligns with the category you would more information about.')
        #T.configure(font=(T['font'],12))
        T.pack(padx=(20,0),pady=(10,10),fill=tk.BOTH,expand=True)
        
        
        T.config(yscrollcommand=scrollbar.set) #configures scroll wheel to work with textbox
        


class scanWebsite: #class for scanning website
    def scanURL(E,T):
        link = E.get()
        T.delete("1.0", tk.END)
        #link = E.get("1.0", "end-1c")
        #print(link)

        #link = E.get()
        
        if not '.' in link: #used to detect invalid url, as url contains '.' in them always so this is used to make the user enter a proper url (something.com) instead of somethingcom.
            #print("You entered an invalid link, you will be redirected in 3 seconds...")
            messagebox.showinfo("Invalid Link", "You entered an invalid link, please double-check your input and try again.")
            return
            #link = input("\nWhat is the URL of the website you would like to scan? (ENTER AS https://domain.com)\n")
        if ' ' in link:
            link.replace(' ','')
        if '/' in link: #used to detect https://, if a user enters it they may only do https:/, this would cause problems so I'm removing all characters including and before /.
            jak = link.split('/', 2)
            #print(jak)
            try:
                link = jak[2]
                #print(link)
            except:
                link = jak[1]
                #print(link)
        #clearTab()
        #frame = tk.Frame(root)
        #frame.pack(fill=tk.BOTH,expand=True)
        #myFrame = tk.Frame(frame)
        #myFrame.pack(side=tk.BOTTOM)
        #T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        #E = tk.Entry(myFrame)
        #link_button = tk.Button(myFrame,text='SCAN URL',command=lambda:scanWebsite.scanURL(E))
        #link_button.pack(side=tk.LEFT)
        #E.pack(side=tk.LEFT,padx=(5,20))
        #mainMenu_button = tk.Button(myFrame,width=30,text='MAIN MENU',command=SafetyAdvice.toMainMenu)
        #mainMenu_button.pack(side=tk.LEFT,pady=10)
        
        #T.insert(tk.END, 'Select the button that aligns with the category you would more information about.')
        #T.pack(padx=20,pady=(10,0))
        link = 'https://' + link #adds https:// to link (this is to account for any typos with https:// the user may have done or if the user did not include https:// at all.
        insertText(T,'SCANNING...')
        url_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=") #used to encode the url into a format that the API can read
        count = 0
        headers = {
        'x-apikey': 'a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f', #used to authenticate my request
        }

        response = requests.get('https://www.virustotal.com/api/v3/urls/' +  url_id, headers=headers) #creating a request to get information about the website 
        #print(response.
        data = json.loads(response.content)
        
        #print(data['data']['attributes']['last_analysis_results'])
        #print(data['data']['attributes']['last_analysis_stats'])
        try:
            stats = data['data']['attributes']['last_analysis_stats']
        except:
            insertText(T, "\n\nWe ran into an issue trying to scan this website, perhaps the website " + str(link) + " doesn't exist? If the website does exist and this problem persits, you can scan this website online with google, simply search for 'scan website google safe browsing' and click on the second link then follow the steps mentioned on there. Feel free to scan another website by pressing the 'Main Menu' button below.")
            return
        #printing what category the website falls under according to reports of the website from external sources.
        try:
            insertText(T,  f"\n\nThe website ({data['data']['attributes']['last_final_url']}) is based around: {data['data']['attributes']['categories']['alphaMountain.ai']}.")
        except:
        #T.insert(tk.END,"\n\nThe website (" + data['data']['attributes']['last_final_url'] + ") is based around: " + data['data']['attributes']['categories']['alphaMountain.ai'] +".")
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
            T.insert(tk.END,". Of the reasons behind the detections, there were:\n  " + str(malicious_reason) + " reports of malicious activity.\n  " + str(err.count('phishing')) + " reports of phishing.")


        #prints advice to the user based on how many reports of malicious activity the website had.
        if stats['malicious'] > 0 and stats['malicious'] <= 5:
            insertText(T, "\n\nAlthough this site has been detected as malicious by a few scanners, this does not mean that the site is safe. Many malware and phishing pages have an embedded security within them to try and trick scanners into thinking it's a regular website. So my advice to you is to be wary of this site, do not download anything from it nor enter any of your personal information on there.")
        
        if stats['malicious'] >= 6:
            insertText(T, "\n\nIt is likely that this site is unsafe. Do not download anything from there or enter any of your personal information if prompted (this includes your usernames, passwords, emails, etc.). If you've already done some of the things mentioned, ensure that you change those details to prevent scammers from logging in to your accounts. If you want to read more information about this, you can restart the program and select 'Safety Advice'.")
        if stats['malicious'] == 0:
            insertText(T, "\n\nThis site has not been detected as malicous by any virus scanners. It is likely safe to use. However brand new websites are not often picked up as malicious so be careful when entering your personal information and if you feel as if something is off, do some research about the website and determine what to do from there.")
        
    def getLink(): #layout for scanning link mode
        clearTab()
        root.title("KEEPMESAFE - Website Scan")
        
        #frame = tk.Frame(root)
        #frame.pack(side=tk.BOTTOM,padx=10,fill=tk.BOTH,expand=True)
        

        frame = tk.Frame(root)
        frame.pack(fill=tk.BOTH,expand=True)
        myFrame = tk.Frame(frame)
        myFrame.pack(side=tk.BOTTOM)
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        
        #retry_button = tk.Button(myFrame,width=30,text='NEW WEBSITE SCAN',command=lambda:scanWebsite.scanURL(T))
        #retry_button.pack(side=tk.LEFT)
        mainMenu_button = tk.Button(myFrame,width=30,text='MAIN MENU',command=SafetyAdvice.toMainMenu)
        
        E = tk.Entry(myFrame)
        link_button = tk.Button(myFrame,text='SCAN URL',command=lambda:scanWebsite.scanURL(E,T))
        link_button.pack(side=tk.LEFT)
        E.pack(side=tk.LEFT,padx=(5,20))
        mainMenu_button.pack(side=tk.LEFT,pady=10)
        
        #T.insert(tk.END, 'Select the button that aligns with the category you would more information about.')
        T.pack(padx=20,pady=(10,0),fill=tk.BOTH,expand=True)
        insertText(T, "Enter the URL of the website you would like to scan in the entry box below, next to the 'SCAN URL' button.")
        


class SafetyAdvice: #layout for advice
    advicePhishing = "PHISHING TIPS:\nBe cautious with emails. Some emails may ask you to visit links. Check the sender's email address and if you don't recognise it, don't click on anything. If you do recognise it but it seems suspicious to you, verify the authenticity of it by speaking with the supposed sender of the email (in case of an organisation, call their support number as sender email addresses can be spoofed.\n\nEnable two-factor authentication on all your accounts to add an additional layer of security. By doing so, somebody that may have your login information to one of your accounts will not be able to access your accounts unless you provide them with the two-factor code (which in most cases, is received through text message.)\n\nBe cautious of what you share on social media. Overly sharing information may lead to people figuring out some of your personal information/passwords. For example, if you share your birth date with social media and your phone passcode happens to be the year of your birthday... it presents a serious risk to your security hence why it's best not to overly share things on social media.\n\nDon't share your personal information like passwords, credit cards etc over the phone or online (unless you know for certain that the website you're sharing this information with is reputable and can be trusted.\n\nDo not trust unsolicited calls or messages, especially from numbers that are claiming to be a part of an organisation (banks for example. Verify the authenticity of the phone call or text message by calling that particular organisation's (that the number might be posing as support number and ask about the call/message you may have received.)\n\nBe careful with links. When visting a website, ensure that the URL that appears in your browser's address bar matches up with what you think the actual website's URL is as although some websites may look the same, it could be an attempt from scammers trying to phish you for your information.\n\nOne of the best things you could do is to educate yourself about this topic, do some research online about phishing and learn about the common strategies that scammers use to lure victims in so you can identify them and prevent yourself from falling victim as well as be able to pass this information on to others, preventing them from falling victim too."
    adviceMalware = "MALWARE TIPS:\nBe cautious with emails. Ensure that you recognise the sender's email address if it's urging you to download a file. If you don't recognise the sender, do not download the file. On the off chance that you do recognise the sender but the email still seems supicious, you can verify its authenticity by speaking with the supposed sender of the email (in the case of an organisation, call their support number as sender email addresses can be easily spoofed by scammers.)\n\nUpdate your softwares, such as your operating system, browsers etc in order to ensure that the security patches of those softwares are up-to-date as you'll be more protected.\n\nIf you can afford anti-virus software, purchase it. It is well worth the investment as it protects you from malicious files that you may download or that may pop up on your system as well as protecting you online from visiting malicious links, thus keeping your personal information safe and your security being almost impenetrable.\n\nBe cautious when downloading things from the internet. To keep yourself safe, ensure that you're only downloading files from reputable sources and scan all files with an anti-virus software. You could even use this prorgram for scanning your files! :)\n\nMake use of adblockers. By using adblockers, you'll be preventing yourself from potentially experiencing malicious ads when visiting websites.\n\nWith malware, prevention is the best defense. So educate yourself about malware, learn how it works, how it's spread etc. Follow the latest cybersecurity news so that you can prevent yourself from falling victim to malware and you can also pass on the knowledge you learn to family and friends, thus preventing them from falling victim to malware as well and keeping more people safe online."
        
    def showPhishing(T):
        T.delete("1.0", tk.END) 

        T.insert(tk.END, SafetyAdvice.advicePhishing)

    def showMalware(T):
        T.delete("1.0", tk.END)  

        T.insert(tk.END, SafetyAdvice.adviceMalware)

    def toMainMenu(): #redirects to mainmenu
        messagebox.showinfo("Main Menu", "You're being redirected to the main menu...")
        mainMenu()
    def showAdvice():
        clearTab()
        root.title("KEEPMESAFE - ADVICE")
        frame = tk.Frame(root)
        frame.pack(padx=10,fill=tk.BOTH,expand=True)

        phishing_button = tk.Button(frame, width=30, text='PHISHING', command=lambda: SafetyAdvice.showPhishing(T)) #lambda used to prevent command from automatically executing (as T variable is passed to function which automatically executes code)
        malware_button = tk.Button(frame, width=30, text='MALWARE', command=lambda: SafetyAdvice.showMalware(T))
        mainMenu_button = tk.Button(frame,width=30,text='MAIN MENU',command=SafetyAdvice.toMainMenu)

        
        
        
        mainMenu_button.pack(pady=(0,10),padx=10,side=tk.BOTTOM,fill=tk.BOTH,expand=True)
        malware_button.pack(padx=10,side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        phishing_button.pack(padx=10,side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        
        T = tk.Text(frame,padx=10,pady=10,wrap=tk.WORD)
        T.insert(tk.END, 'Select the button that aligns with the category you would more information about.')
        scrollbar = tk.Scrollbar(frame, command=T.yview)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y,padx=(0,15),pady=10 )
        T.pack(padx=(20,0),pady=(10,10))
        
        
       
        
        

        T.config(yscrollcommand=scrollbar.set)
        
root = tk.Tk()
      
            
def mainMenu(): #layout for starting page / main menu
    clearTab()
    root.title("KEEPMESAFE - MAIN MENU")
    root.geometry('800x600')
    #root.geometry('320x260')
    # Create a textbox
    entry = tk.Entry(root, width=50)  
    #entry.pack(fill=tk.BOTH,expand=True)
    
   
    button1 = tk.Button(root, width=30,text="WEBSITE SCANNING",command=scanWebsite.getLink)
    button1.pack(fill=tk.BOTH,expand=True)

    button2 = tk.Button(root, width=30,text="FILE SCANNING",command=scanFile.fileScanSetup)
    button2.pack(fill=tk.BOTH,expand=True)

    button3 = tk.Button(root, width=30,text="SAFETY ADVICE", command=SafetyAdvice.showAdvice)
    button3.pack(fill=tk.BOTH,expand=True)
    try:
        root.mainloop()
    except:
        pass

mainMenu()

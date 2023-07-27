import requests
import time
import json
import base64
import pyfiglet
import tkinter as tk
from tkinter import filedialog
import sys



title = pyfiglet.figlet_format("Keep Me Safe!", font = "bulbhead" ) #prints title of program in cool font
print(title)


def modeSelect(): # asks user which mode they would like to use
    global mode
    mode = int(input("Which mode would you like to use? \n  [1] SCAN A WEBSITE\n  [2] SCAN A FILE\n  [3] SAFETY ADVICE\n"))
    

def correctValue():
    try: # calls upon modeselect, if user enters a value that is not 1, 2 or 3 then they will be redirected to the start
        modeSelect()
        if mode != 1 and mode != 2 and mode !=3: #if user enters invalid number
            print("You entered an invalid digit. Be sure to enter the digit associated with the mode you want to select, you will be redirected in 3 seconds.")
            time.sleep(3)
            redirToValue()   
    except: #if user enters completely invalid value
        print("You entered an invalid value. Be sure to enter the number value associated with the mode you want to select. You will be redirected in 3 seconds.")
        time.sleep(3)
        redirToValue()

def redirToValue():
    correctValue()
    
def getLink(): #asks user for url they want to scan
        global link 
        link = input("\nWhat is the URL of the website you would like to scan? (ENTER AS https://domain.com)\n")
        websiteScan()
        
def websiteScan(): # process of scanning URL
    global link
    while not '.' in link: #used to detect invalid url, as url contains '.' in them always so this is used to make the user enter a proper url (something.com) instead of somethingcom.
        print("You entered an invalid link, you will be redirected in 3 seconds...")
        time.sleep(3)
        link = input("\nWhat is the URL of the website you would like to scan? (ENTER AS https://domain.com)\n")
    if '/' in link: #used to detect https://, if a user enters it they may only do https:/, this would cause problems so I'm removing all characters including and before /.
        jak = link.split('/', 2)
        #print(jak)
        try:
            link = jak[2]
            #print(link)
        except:
            link = jak[1]
            #print(link)
    link = 'https://' + link #adds https:// to link (this is to account for any typos with https:// the user may have done or if the user did not include https:// at all.
    print("\nSCANNING...")
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
        print("\nWe ran into an issue trying to scan this website, perhaps the website " + str(link) + " doesn't exist? If the website does exist and this problem persits, you can scan this website online with google, simply search for 'scan website google safe browsing' and click on the second link then follow the steps mentioned on there.")
        input("\nPress ENTER to exit")
        sys.exit()
    try:
        #printing what category the website falls under according to reports of the website from external sources.
        print("\nThe website (" + data['data']['attributes']['last_final_url'] + ") is based around: " + data['data']['attributes']['categories']['alphaMountain.ai'] +".", end = "")
        if data['data']['attributes']['categories']['alphaMountain.ai'] == 'Unrated':
            print(" This may potentially be a new website, be careful.\n") #if category is unrated, may indicate that website is brand new hence my warning
    except:
        pass
    #telling user how many scanners the website submitted was detected as malicious by, out of 90 total scanners that are used in VirusTotal api for web scanning.
    print("\n\nAccording to our analysis, the website: " + data['data']['attributes']['last_final_url'] + " is detected as malicious by " + str(stats['malicious']) + ' malware/phishing scanners (out of 90)')
    if stats['malicious'] > 0:
        err = str(data['data']['attributes']['last_analysis_results'])
        malicious_reason = err.count('malicious') - stats['malicious']
        #details the type of malicious activity that's been detected on the website the user hass submitted
        print("Of the reasons behind the detections, there were:\n  " + str(malicious_reason) + " reports of malicious activity.\n  " + str(err.count('phishing')) + ' reports of phishing.')


    #prints advice to the user based on how many reports of malicious activity the website had.
    if stats['malicious'] > 0 and stats['malicious'] <= 5:
        print("\nAlthough this site has been detected as malicious by a few scanners, this does not mean that the site is safe. Many malware and phishing pages have an embedded security within them to try and trick scanners into thinking it's a regular website. So my advice to you is to be wary of this site, do not download anything from it nor enter any of your personal information on there.")
    
    if stats['malicious'] >= 6:
        print("\nIt is likely that this site is unsafe. Do not download anything from there or enter any of your personal information if prompted (this includes your usernames, passwords, emails, etc.). If you've already done some of the things mentioned, ensure that you change those details to prevent scammers from logging in to your accounts. If you want to read more information about this, you can restart the program and select 'Safety Advice'.")
    if stats['malicious'] == 0:
        print("\nThis site has not been detected as malicous by any virus scanners. It is likely safe to use. However brand new websites are not often picked up as malicious so be careful when entering your personal information and if you feel as if something is off, do some research about the website and determine what to do from there.")
    input("\nPress ENTER to close the program")

    
def fileScan():
    print("\nYou will be prompted to select the file you would like to have scanned in 3 seconds...")
    time.sleep(3)
    #using tkinter to open a file select dialog for user to easily select file you would like to have scanns
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select the file you would like to scan")

    scan_type = int(input("Types of scans:\n  [1] QUICK SCAN (NOT AS ACCURATE, FILE SIZE LIMIT OF 3 MB, NOT ALL FILE TYPES SUPPORTED)\n  [2] ADVANCED SCAN (ACCURATE, FILE SIZE LIMIT OF 64MB, MAY TAKE UP TO TEN MINUTES)\n"))

    if scan_type == 1: #quick scan
        headers = {
            'Apikey': '7d1e1d3f-5240-4ed4-98ef-ef8932a12c42',
        }

        files = {
            'inputFile': open(file_path, 'rb'),
        }
        try:
            response = requests.post('https://api.cloudmersive.com/virus/scan/file', headers=headers, files=files)
        except:
            #in case of an error uploading the to the cluoudmerisve api
            print("THERE WAS AN ERROR UPLOADING YOUR SELECTED FILE, PERHAPS YOUR TYPE OF FILE IS NOT SUPPORTED IN THIS MODE. TRY THE ADVANCED SCAN INSTEAD.")
        if 'Input file was larger than the limit' in str(response.content):
            print("YOUR SELECTED FILE EXCEEDED THE SIZE LIMIT. TO UPLOAD THIS FILE, USE THE ADVANCED SCAN OPTION INSTEAD")
            input("Press ENTER to exit")
            sys.exit()
        results = json.loads(response.content)
        if results['CleanResult'] == True: #if file is scanned and found to be clean
            print("According to a quick scan of your file, there were no threats detected on it. If you've downloaded this from a reputable site (such as Microsoft, Adobe etc), you will be fine. However, if you've downloaded this off of a site you're not too familiar with, I recommend that you run the file through the advanced scan as well, this is because malware that hasn't been spread to a lot of computers will not get picked up under the quick scan feature.") 
            input("\nPress ENTER to exit")
            sys.exit()
        elif results['CleanResult'] == False: #if file is scanned and found to be malicious
            print("After an analysis of your file, we've found malicious content within the file that could be harmful for your computer. Do not open this file, instead permanently delete that. If you've already opened this file, then I recommend you use an antivirus software such as MalwareBytes or McAfee to try and remove the file from your system processes. If that doesn't work, I recommend that you reset your system back to your computer's last restore point, you can find how to do this on Youtube. Be wary of the files that you download from the internet.")
            input("\nPress ENTER to exit")
            sys.exit()
    elif scan_type == 2: # advanced scan
        print("UPLOADING FILE TO WEBSERVER FOR ANALYSIS")
        url = "https://www.virustotal.com/api/v3/files"

        files = {"file": (file_path, open(file_path, 'rb'))}
        headers = {
        "accept": "application/json",
        "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"
        }

        try:
            response = requests.post(url, files=files, headers=headers) #uploading file 
        except:
            print("\nTHERE WAS AN ERROR UPLOADING YOUR SELECTED FILE, PERHAPS THE SIZE OF YOUR FILE IS OVER 64MB. PLEASE MAKE USE OF A REPUTABLE ANTI-VIRUS SCANNER SUCH AS MCAFEE TO SCAN THIS FILE.")
            input("\nPress ENTER to exit")
            sys.exit()
        
        grr = json.loads(response.text) #formatting response text into json for easy-to-read format
        file_id = grr['data']['id'] # calling upon file id from json response for reference in next API call 
        

        
        #analyse file
        url = "https://www.virustotal.com/api/v3/analyses/" + str(file_id) #this api requires file id within url hence why file id is added

        headers = {
        "accept": "application/json",
        "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"
        }

        response = requests.get(url, headers=headers) #api is scanning file
        print("\nSCANNING FILE")
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
            print("    [+] STILL SCANNING...")

        
        
        md5 = getmd5['meta']['file_info']['md5'] #md5 hash within the json response, used for next api call
        
        
        #file report
        url = "https://www.virustotal.com/api/v3/files/" + str(md5) #md5 needed in url for api call hence why string md5 is in url
        headers = {"accept": "application/json", "x-apikey": "a5c84ce0b02389f1df6ad30367f31568425726be1fe3dbebd9aa1e114a84f41f"}
        response = requests.get(url, headers=headers)

        
        file_report = json.loads(response.text) #converting the response string format into json format to easily read and get information
        scan_amount = file_report['data']['attributes']['times_submitted'] #how many times file was scanned on virustotal api
        file_name = file_report['data']['attributes']['meaningful_name'] #name of file user uploaded for scanning
        file_stats = file_report['data']['attributes']['last_analysis_stats'] # compilation of virus scanners' analysis stats, malicious, safe etc
        print("The file you've uploaded, " + file_name + " has been submitted for scanning " + str(scan_amount) + " times (from you and other people).")
        total_scanner_count = file_stats['malicious'] + file_stats['undetected'] # adding up stats of undetected and malicious results to calculate total amount of virus scanners used 
        print("\nAccording to our analysis of the file, " + str(file_stats['malicious'])  + " out of " + str(total_scanner_count) + " scanners used have reported the file as malicious.")
       
        end = time.time()
        time_taken = end - start
        print("Time taken: " + "%.2f" % time_taken + " seconds") #measuring how long it took to scan file
        

        if file_stats['malicious'] == 0: #giving advice to the user bsaed on how many counts of maliciousness the file has
            print("\nIt's likely that the file you've submitted does not oontain any type of virus and is safe to use. However, some malware that is brand-new and hasn't been seen before is not likely to get picked up as malicious, therefore ensure the authenticity of this file... ensure you've downloaded it directly from the application's page and not frmo a third party to keep yourself safe.")
        elif file_stats['malicious'] > 0 and file_stats['malicious'] <= 5:
            print("\nThe file has been flagged by a few scanners, they may be false-positives (falsley detected as malicious) but treat this file with caution. Ensure you've downloaded it from a reputable website and that it's absolutely necessary to use. For safety, I recommend using this file within a virtual machine so that if the file does contain malware, your actual machine will be safe (as only the virtual machine would be affected).") 
        elif file_stats['malicious'] >=6:
            print("\nThe file you've submitted has been flagged by multiple scanners, it is likely that this file contains malware. Permanently delete this file from your system, DO NOT OPEN IT. If you'd like to learn more information about malware, you can restart the program and select 'Safety Advice'.")
        
        askSave = input("\nWould you like to save the full report of the scan on your file you've submitted? YES/NO?\n")
        if askSave.upper() == "YES" or askSave.upper() == "YE" or askSave.upper() == "Y": #saving detailed report of file
            saveName = file_name.replace('.', ' ') 
            f = open(str(saveName) + ' Report.txt', 'w')
            saveContent = str(file_report['data']['attributes']['last_analysis_results']).replace('},', '\n') 
            saveContent = saveContent.replace('{', '')
            f.write(saveContent)
            f.close()
            print("Succesfully saved the report in the same folder as the program, under the name: " + str(saveName) + " Report.txt\n") 
            input("\nPRESS ENTER TO EXIT")
            sys.exit()

tipsMode = 0       
  
        
    
             
def infoDisplay(): #displays information about phishing and malware
    global tipsMode
    while tipsMode == 0: #loop to force user to select correct tipsMode value in case of error so they can view tips for the associated category
        try:
            tipsMode = int(input("Which category would you like to learn more information about?\n [1] - PHISHING\n [2] - MALWARE\n"))
            if tipsMode != 1 and tipsMode != 2:
                print(tipsMode)
                print("You did not enter a valid value. Ensure to enter the number associated with the category you would like to learn more about. You will be redirected in 3 seconds.")
                time.sleep(3)
                tipsMode = 0
        except:
            print("You did not enter a valid value. Ensure to enter the number associated with the category you would like to learn more about. You will be redirected in 3 seconds.")
            time.sleep(3)

    
    if tipsMode == 1: #displays tips about phishing prevention
        print("\nPHISHING TIPS:\nBe cautious with emails. Some emails may ask you to visit links. Check the sender's email address and if you don't recognise it, don't click on anything. If you do recognise it but it seems suspicious to you, verify the authenticity of it by speaking with the supposed sender of the email (in case of an organisation, call their support number) as sender email addresses can be spoofed.")
        print("\nEnable two-factor authentication on all your accounts to add an additional layer of security. By doing so, somebody that may have your login information to one of your accounts will not be able to access your accounts unless you provide them with the two-factor code (which in most cases, is received through text message")
        print("\nBe cautious of what you share on social media. Overly sharing information may lead to people figuring out some of your personal information/passwords. For example, if you share your birthdate with social media and your phone passcode happens to be the year of your birthday... it could present a very serious risk to your security hence why it's best not to overly share things on social media.")
        print("\nDon't share your personal information like passwords, credit cards etc over the phone or online (unless you know for certain that the website you're sharing this information with is reputable and can be trusted).")
        print("\nDo not trust unsolicited calls or messages, especially from numbers that are claiming to be a part of an organisation (banks for example). Verify the authenticity of the phone call or text message by calling that particular organisation's (that the number might be posing as) support number and ask about the call/message you may have received.")
        print("\nBe careful with links. When visting a website, ensure that the URL that appears in your browser's address bar matches up with what you think the actual website's URL is as although some websites may look the same, it could be an attempt from scammers trying to phish you for your information.")
        print("\nOne of the best things you could do is to educate yourself about this topic, do some research online about phishing and learn about the common strategies that scammers use to lure victims in so you can identify them and prevent yourself from falling victim as well as be able to pass this information on to others, preventing them from falling victim too.")
        input("\nPress ENTER to exit")
        sys.exit()
    if tipsMode == 2: #displays tips about malware prevention
        print("\nMALWARE TIPS:\n Be cautious with emails. Ensure that you recognise a sender's email address if it's urging you to download a file. If you don't recognise the sender, do not download the file. On the off chance you do recognise the sender, but the email seems supicious, verify its authenticity by speaking with the supposed sender of the email (in case of an organisation, call their support numebr) as sender email addresses can be easily spoofed by scammers.")
        print("\nUpdate your softwares, such as your operating system, browsers etc to ensure that the security patches of those softwares are up-to-date as you'll be more protected.")
        print("\nIf you can afford anti-virus software, purchase it. It is well worth the investment as it protects you from malicious files that you may download or that may pop up on your system as well as protecting you online from visiting malicious links, thus keeping your personal information safe and your security being almost impenetrable.")
        print("\nBe cautious when downloading things from the internet. TO keep yourself safe, ensure that you're only downloading from reputable sources and scan all files with an anti-virus software | you could use us for scanning your files! :)")
        print("\nMake use of adblockers. By using adblockers, you'll be preventing yourself from potentially experiencing malicious ads when visiting websites.")
        print("\nWith malware, prevention is the best defense. So educate yourself about malware, learn how it works, how it's spread etc. Follow the latest cybersecurity news so that you can prevent yourself from falling victim to malware and you can also pass on the knowledge you learn to family and friends, thus preventing them from falling victim to malware as well and keeping more people safe online.")
        input("\nPress ENTER to exit")
        sys.exit()

        
correctValue() #starts off program, asking user to select mode
if mode == 1:
    getLink() #redirects to website scan function
if mode == 2:
    fileScan() #redirects to file scan function
if mode == 3:
    infoDisplay() #redirects to tips & tricks function


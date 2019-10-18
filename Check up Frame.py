import os,sys
from datetime import datetime
import yara
import Tkinter
from Tkinter import * 
import Tkinter, Tkconstants, tkFileDialog, tkMessageBox

############################################################ Create GUI Frame for Check up Virus ############################################################

window = Tkinter.Tk()
window.title("Check Files Using Yara")
window.geometry("430x260+750+250")
window.resizable(True,True)

yar_path = Tkinter.StringVar()
checkup_path = Tkinter.StringVar()
Report_path = Tkinter.StringVar()

def select_yar_file():
    global yar_path
    filename=tkFileDialog.askopenfilename(title="Select Rule File",filetypes=(("all files","*.*"),("Yar Files","*.yar")))
    yar_path.set(filename)

def select_Checkup_Dir():
    global checkup_path
    dirname=tkFileDialog.askdirectory(title='Select Checkup DIR')
    checkup_path.set(dirname)

def select_Report_Dir():
    global Report_path
    dirname=tkFileDialog.askdirectory(title='Select Report DIR')
    Report_path.set(dirname)

def check_string(yar_path,checkup_path,Report_path):
    
    if yar_path.get() == '' or checkup_path.get() == '' or Report_path.get() == '':
        tkMessageBox.showerror("오류","YAR 파일 경로 & 검사 대상 폴더 경로 & 보고서 저장 폴더 경로를 모두 선택하여 주세요")

    else:
        ask = tkMessageBox.askyesno("Check Files Using Yara","검사를 실행하시겠습니까?")
        if ask:
            Check_Main(yar_path,checkup_path,Report_path)

def Frame():

    ############################ YAR Rule Select GUI ####################################

    labelframe1=Tkinter.LabelFrame(window,width=400,height=55,text="YAR RUle File Select")
    labelframe1.place(x=10,y=10)

    #select YAR Rule File Select
    entry=Tkinter.Entry(window,width = 45,state="readonly",textvariable=yar_path)
    entry.place(x=20,y=35)

    button = Tkinter.Button(window,width=5,command=select_yar_file, repeatdelay=1000, repeatinterval=100,text="...")
    button.place(x=350,y=30)

   ############################ Checkup DIR Select GUI ####################################

    labelframe2=Tkinter.LabelFrame(window,width=400,height=55,text="Check UP DIR Select")
    labelframe2.place(x=10,y=80)

    entry2=Tkinter.Entry(window,width = 45,state="readonly",textvariable=checkup_path)
    entry2.place(x=20,y=105)

    button2 = Tkinter.Button(window,width=5,command=select_Checkup_Dir, repeatdelay=1000, repeatinterval=100,text="...")
    button2.place(x=350,y=100)

    ############################ Report DIR Select GUI ####################################

    labelframe3=Tkinter.LabelFrame(window,width=400,height=55,text="Report DIR Select")
    labelframe3.place(x=10,y=150)

    entry3=Tkinter.Entry(window,width = 45,state="readonly",textvariable=Report_path)
    entry3.place(x=20,y=175)

    button3 = Tkinter.Button(window,width=5,command=select_Report_Dir, repeatdelay=1000, repeatinterval=100,text="...")
    button3.place(x=350,y=170)

    #################################### Start GUI ########################################

    start_button = Tkinter.Button(window,width=8,height=2,command=lambda:check_string(yar_path,checkup_path,Report_path),text="START")
    start_button.place(x=320,y = 210)

    #######################################################################################

    window.mainloop()

##########################################################################################################################################

################################################### Check up signature using YARA in Files ###############################################

def getfilelist(DirPath):

    file_list=[]
    
    for root, dirs, files in os.walk(DirPath):

        rootpath = os.path.join(os.path.abspath(DirPath), root)

        for file in files:
            filepath = os.path.join(rootpath, file)
            file_list.append(filepath)
            
    return file_list

def complite_yar_rule(yar_path):
    rules = yara.compile(filepath=yar_path)
    return rules

def Check_file(file_list,rules):

    Report_Content = []
    result_text = ""

    for file in file_list:
    
        # Check the rules in the file.     
        try:
            match_results = rules.match(file)

            if len(match_results) > 0:
                result_text = file + " - "
                
                for result in match_results:
                    result_text += str(result)

                    if result != match_results[-1]:
                        result_text += ", "
               
                Report_Content.append(result_text)
                result_text = ""
                
        except Exception as e:

            # Exclude zero length file
            if str(e).find('zero length file') > -1:
                pass
            else:
                print(e)

    return Report_Content

def Create_Report(Report_path,Report_Content):

    date = datetime.now()
    name_time = date.strftime("%Y_%m_%d_%H_%M_Report.txt")
    Report_Save_Path = Report_path.get().encode('cp949') + "/" + name_time
    
    f = open(Report_Save_Path,'w')

    for content in Report_Content:
        content = content.replace("\\","/")
        f.write(content + "\n")

    f.close()

    return Report_Save_Path

def Check_Main(yar_path,checkup_path,Report_path):

    # Get Files List
    file_list = getfilelist(checkup_path.get().encode('cp949'))

    # Complite yar Rule
    rules = complite_yar_rule(yar_path.get().encode('cp949'))
    
    # Match Files & Get RESULT
    Report_Content = Check_file(file_list,rules)

    # Create Report
    Report_Save_Path = Create_Report(Report_path,Report_Content)

    message = "총 " + str(len(Report_Content)) + "개의 악성행위 의심 파일이 발견되었습니다.\n 보고서 파일을 열람하시겠습니까?"
    ask = tkMessageBox.askyesno("Check Completed",message)

    if ask:
        Report_Save_Path.replace("/","\\")
        os.system("\"" + Report_Save_Path + "\"")

#############################################################################################################################################

##################################################### Create GUI (First Start) ##############################################################
Frame()

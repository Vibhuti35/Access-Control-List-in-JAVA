package acl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

public class ACL {

    public static void main(String[] args) {
        // TODO code application logic here
     //Standard and extended ACLs and input files
     String ACL = "/Users/vibhutipatel/Desktop/MACS/Network Security/Assignment2/StandardACL.txt";
     String SandardACL="/Users/vibhutipatel/Desktop/MACS/Network Security/Assignment2/StandardACLinput.txt";
     String ExtendedACL="/Users/vibhutipatel/Desktop/MACS/Network Security/Assignment2/ExtendedACL.txt";
     String ExtendedACLinput="/Users/vibhutipatel/Desktop/MACS/Network Security/Assignment2/ExtendedACLinput.txt";
     
     //Array list to store data from file
     ArrayList<String> acl= new ArrayList<String>();
     ArrayList<String> ip= new ArrayList<String>();
     ArrayList<String> exacl= new ArrayList<String>();
     ArrayList<String> exip= new ArrayList<String>();
     String line,line1 = null,protocol=null;
     int Count=0,Counte=0;
     boolean sflag=true,sflagany=true,eflag=true,eflagany=true;
     
        System.out.println("-----------------------STANDARD------------------------");
        try{
            //Reading standard ACL from file and storing it to arraylist
        FileReader fr=new FileReader(ACL);
        BufferedReader in = new BufferedReader(fr);
        
        while((line = in.readLine()) != null)
            {
                if(line.contains("access-list"))
                {
                //System.out.println(line);
                acl.add(line);
                }
            }
            in.close();
            
        // Reading input to be given from file and storing it to arraylist   
        FileReader fr1=new FileReader(SandardACL);
        BufferedReader in1 = new BufferedReader(fr1);
        
        while((line1 = in1.readLine()) != null)
            {
                //System.out.println(line1);
                ip.add(line1);
            }
            in1.close();

            //Iterating input arraylist
            for(int i=0;i<ip.size();i++)
            {
                //Spliting ip by '.'
                String[] iptemp=ip.get(i).split("\\.");
                //Iterating ACL arraylist
                for(int a=0;a<acl.size();a++)
                {
                   //Spliting by space and then .
                    String[] acltemp = acl.get(a).split("\\s");
                    String aclip=acltemp[3];
                    //Setting the flag if 'any' source can be permitted or denied no need to check other conditions
                    if(acltemp[3].contains("any")) { sflagany=false; }
                    if(sflagany==true) 
                    {
                    String mask=acltemp[4];
                    //Splitting source and mask ip by '.'
                    String[] aclipsplit=aclip.split("\\.");
                    String[] masksplit=mask.split("\\.");
                   
                    //Checking if any element contains '0' if it then only check the conditions
                    for(int j=0;j<4;j++)
                    {
                        //System.out.println(j);
                        if(masksplit[j].contains("0"))
                        {
                            //If input ip matches with ACL ip
                            if(!iptemp[j].contains(aclipsplit[j]))
                            {
                                sflag=false;
                            }
                            
                            if(sflag==false)
                                
                            { 
                                break;
                            }
                        }
                    } 
                }
                     sflagany=true;
                     //if all ip elements match then check if it needs to be deny then print
                    if(sflag==true && acltemp[2].contains("deny"))
                    {
                       System.out.println(ip.get(i)+ "    denied");
                       Count++;  
                       break;
                    
                    }
                    //if all ip elements match then check if it needs to be permit then print
                    else if(sflag==true && acltemp[2].contains("permit"))
                    {
                            System.out.println(ip.get(i)+ "     permitted");
                        Count++;  
                        break;
                    
                    }
                    
                   sflag=true;     
                }
                //If it doesn't match any conditions it is denied
                if(Count==0)
                    {
                        System.out.println(ip.get(i)+"      denied");
                       
                    }
                Count=0;
            }
        }
        catch(Exception e)
        {
           System.out.println("Error:"+e);
        }  
        
        System.out.println("-----------------------EXTENDED------------------------");
        
        try{
            ////Reading extended ACL from file and storing it to arraylist
        FileReader fr=new FileReader(ExtendedACL);
        BufferedReader in = new BufferedReader(fr);
        
        while((line = in.readLine()) != null)
            {
                if(line.contains("access-list"))
                {
                //System.out.println(line);
                exacl.add(line);
                }
            }
            in.close();
         // Reading input to be given from file and storing it to arraylist 
        FileReader fr1=new FileReader(ExtendedACLinput);
        BufferedReader in1 = new BufferedReader(fr1);
        
        while((line1 = in1.readLine()) != null)
            {
                //System.out.println(line1);
                exip.add(line1);
            }
            in1.close();
            //System.out.println(exip);
            //System.out.println(exacl);
            
            for(int i=0;i<exip.size();i++)
            {
                String[] iptemp=exip.get(i).split("\\s");
                //System.out.println("0:"+iptemp[0]+" 1:"+iptemp[1]+" 2:"+iptemp[2]+"");
                String[] sourceip=iptemp[0].split("\\.");
                String[] destinationip=iptemp[1].split("\\.");
                //Checking the protocol in input and assinging the port number to check with the ACL 
                if(iptemp[2].contains("ftp")){ protocol="20-21"; }
                else if(iptemp[2].contains("http")) {protocol="80";}
                else if(iptemp[2].contains("ssh")) {protocol="22";}
                else if(iptemp[2].contains("snmp")) {protocol="161";}
                
                for(int a=0;a<exacl.size();a++)
                {
                    String[] acltemp = exacl.get(a).split("\\s");
                    
                  if((acltemp[4].contains("any") && acltemp[4].contains("any")) ) { eflagany=false;}
                  
                  if(eflagany==true){
                    //If the protocol matches or not
                    if(acltemp[9].contains(protocol))
                    {
                        //Splitting the ips and masks from ACL and storing it to string array
                        String[] sourceacl=acltemp[4].split("\\.");
                        String[] sourcemask=acltemp[5].split("\\.");
                        String[] destinationacl=acltemp[6].split("\\.");
                        String[] destinationmask=acltemp[7].split("\\.");
                    
                        for(int k=0;k<4;k++)
                        {
                            //Checking if the source ip is matching or not
                            if(sourcemask[k].contains("0"))
                            {
                                if(!sourceip[k].contains(sourceacl[k]))
                                {
                                    eflag=false;
                                }
                            }
                            
                           //If not matches then break the loop
                            if(eflag==false)
                            {
                                break;
                            }
                            
                            else
                            {
                                //Checking if the destination ip is matching or not
                                if(destinationmask[k].contains("0"))
                                {
                                    if(!destinationip[k].contains(destinationacl[k]))
                                    {
                                        eflag=false;
                                    }
                                }
                            }
                            
                            if(eflag==false)
                            {
                                break;
                            }
                        }
                        
                        
                        //if all ip elements match then check if it needs to be deny then print
                         if(eflag==true && acltemp[2].contains("deny"))
                            {
                                System.out.println(iptemp[0]+ "    denied");
                                Counte++; 
                    
                            }
                         else if(eflag==true && acltemp[2].contains("permit"))
                            {
                                System.out.println(iptemp[0]+ "     permitted");
                                Counte++;  
                    
                            }
                   
                        eflag=true;                        
                     }
                    
                  }
                  
                  else
                  {
                      //In case of any other source and destination is permitted or denied
                       //System.out.println("Any");
                      if(acltemp[2].contains("deny"))
                            {
                                System.out.println(iptemp[0]+ "    denied");
                                Counte++; 
                    
                            }
                         else if(eflag==true && acltemp[2].contains("permit"))
                            {
                                System.out.println(iptemp[0]+ "     permitted");
                                Counte++;  
                            }
                     
                      eflagany=true;
                  }
                  
                        //If already compared with ACL then break and check the next input
                         if(Counte!=0)
                         {
                               break;
                         }
                }
                
                //If no matching ACLs found then by default it is denied
                if(Counte==0)
                {
                    System.out.println(iptemp[0]+ "denied");
                }
                Counte=0;
                   
            }
               
        }
        catch(Exception e)
        {
            System.out.println("Error:"+e);
        }
        
        
    }   
}
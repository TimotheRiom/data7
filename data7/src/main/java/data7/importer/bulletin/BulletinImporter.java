package data7.importer.bulletin;


import data7.Resources;
import miscUtils.Misc;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.time.Year;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static data7.Utils.checkFolderDestination;
/**


*/
public class BulletinImporter {

    /**
     * TODO : change path: String into path: RessourcesPath
     * TODO : update mode according to what is already in the files
     */
    private String baseUrl="https://source.android.com";
    private String indexUrlPath="/security/bulletin/";
    private List<String> releasedBulletins=null;
    private String path=null;
    private String regexpURL="/security/bulletin/[0-9]{4}-[0-9]{2}-[0-9]{2}.html\">English";
    private List<List<String>> vulnerabilityList;

    /**
     *
     *
     *param
     *return
     * throws
    */
    BulletinImporter(String path) throws FileNotFoundException, IOException{
        this.path=path;
        vulnerabilityList= new ArrayList<>();
        updateReleasedBulletinsList();

        //Under Work
        getPatchFromMonthly(releasedBulletins.get(5));
    }

    /**
     *
     *
     *param
     *return List<String,String> of <CVE, [patchURLName]>, not yet vulnerability but here it comes
     * throws
     */
    private void getPatchFromMonthly (String monthlyBulletinURL)throws FileNotFoundException, IOException{
        /** We will download using MiscUtils.Misc::downloadFromURL and then parse it to get the CVE and patch links */
        /**Create Folder or check if exists*/
        String dlPath=this.path+"/Monthly/";
        checkFolderDestination(dlPath);
        /**DownloadPage*/
        Misc.downloadFromURL((monthlyBulletinURL),dlPath);
        /**Parse and store URLs of patches*/
        FileReader fReader=new FileReader( dlPath+"/"+monthlyBulletinURL.substring(45) );
        BufferedReader brTest = new BufferedReader(fReader);
        String htmlLine = brTest.readLine();
        while (htmlLine!=null){
            /**if Match on <table> */
            Pattern pattern=Pattern.compile("<table>");
            Matcher m=pattern.matcher(htmlLine);
            if (m.find()){
                /** While no match on </table>, take nextLine on htmlLine */
                pattern=Pattern.compile("<\\/table>");
                m=pattern.matcher(htmlLine);
                while(!m.find()) {
                    /**if match on CVE-[]{4}-[]+ */
                    List<String> localVulnerabilityList=new ArrayList<>();
                    Pattern patternCVE =Pattern.compile("CVE-[0-9]{4}-[0-9]+<");
                    Matcher mCVE=patternCVE.matcher(htmlLine);
                    if(mCVE.find()) {
                        String var=mCVE.group(0).substring(0,mCVE.group(0).length()-1);
                        localVulnerabilityList.add((String) (mCVE.group(0).substring(0,mCVE.group(0).length()-1)));// retrieving the '<'
                        /**nextLine, while href to retrieve: match on href android.googlesource stg take it and save it   */
                        //brTest.readLine();
                        htmlLine = brTest.readLine();
                        Pattern patternhref=Pattern.compile("href=\"https:\\/\\/android.googlesource.com[\\/[a-z]+]+\\+\\/[a-z0-9]+");
                        Matcher mhref=patternhref.matcher(htmlLine);
                        while(mhref.find()){
                            //or not depending
                            localVulnerabilityList.add(mhref.group(0).substring(6));
                            brTest.readLine();// Skipping the line after a href for now, later TODO shall we get the A-[0-9]+ ref ?
                            htmlLine = brTest.readLine();
                            mhref=patternhref.matcher(htmlLine);
                        }

                    }
                    if (localVulnerabilityList!= null && localVulnerabilityList.size()>1  ){
                        this.vulnerabilityList.add(localVulnerabilityList);
                    }
                    /**     looking if we are out of the table */
                    htmlLine = brTest.readLine();
                    m=pattern.matcher(htmlLine);
                }
            }
            htmlLine = brTest.readLine();
        }
        brTest.close();
        fReader.close();

    }

    /**
     * Using the actual year, this function is meant to fetch all the bulletins released on the baseUrl website and store them in releasedBulletins for proper scrape of cves later on
     *
     *param
     *return
     * throws
     */
    private void updateReleasedBulletinsList() throws FileNotFoundException , IOException {
        int currentYear=Year.now().getValue();
        String indexURL;
        int yearCounter=2015;/** Starting year of the bulletins*/
        releasedBulletins=new ArrayList<>();
        for (yearCounter=2015;yearCounter<=currentYear;yearCounter++){
            indexURL=this.baseUrl+this.indexUrlPath+String.valueOf(yearCounter);

            /** We will download using MiscUtils.Misc::downloadFromURL and then parse it to get the links of monthly androids bulletins */
            /**Create Folder or check if exists*/
            checkFolderDestination(this.path);
            /**DownloadPage*/
            Misc.downloadFromURL((indexURL),this.path);
            /**Parse and store URLs of monthly bulletin*/
            FileReader fReader=new FileReader(path+"/"+String.valueOf(yearCounter) );
            BufferedReader brTest = new BufferedReader(fReader);
            String htmlLine = brTest.readLine();
            while (htmlLine!=null){
                Pattern pattern=Pattern.compile(regexpURL);
                Matcher m= pattern.matcher(htmlLine);
                if (m.find()){
                        releasedBulletins.add(baseUrl+m.group(0).substring(0,m.group(0).length()-9));
                        //System.out.println("--DEBUGLINE--"+htmlLine);
             }
                htmlLine = brTest.readLine();
            }
            /** ?? Suppress file ?? not if we want update mode later on*/


            brTest.close();
            fReader.close();
        }

    }

    /**
     * param
     * return
     * throws
    */
    public static void main(String[] args) throws FileNotFoundException, IOException{
        String folderToDownloadIn= "/home/user1/Desktop/Tools/Vulnerabilities/test/listBulletins";
        BulletinImporter bImporter=new BulletinImporter(folderToDownloadIn);

    }
}

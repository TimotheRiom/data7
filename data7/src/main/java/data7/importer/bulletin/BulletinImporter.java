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
     *param path: String, toward which the file might be saved
     *return
     * throws
    */
    BulletinImporter(String path) throws FileNotFoundException, IOException{
        this.path=path;
        vulnerabilityList= new ArrayList<>();
        updateReleasedBulletinsList();

        //Under Work
        getPatchFromMonthly(releasedBulletins.get(0));
        getPatchFromMonthly(releasedBulletins.get(1));
    }

    /**
     *On th page of a monthly bulletin, this function is supposed to update the list of CVE retrieved : List<String,String> of <CVE, <patchURLName>>, not yet vulnerability but here it comes
     *
     *param String monthlyBulletinURL, the URL of one of the Android Bulletins
     *return
     * throws
     */
    private void getPatchFromMonthly (String monthlyBulletinURL)throws FileNotFoundException, IOException{
        int hrefLineThreshold=0;
        int nbDebugLine=0;
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
        nbDebugLine+=1;
        while (htmlLine!=null){
            /**if Match on <table> */
            Pattern pattern=Pattern.compile("<table>");
            Matcher m=pattern.matcher(htmlLine);
            if (m.find()){
                /** While no match on </table>, take nextLine on htmlLine */
                pattern=Pattern.compile("<\\/table>");
                m=pattern.matcher(htmlLine);
                boolean exitTable=m.find();
                while(!exitTable) {
                    /**if match on CVE-[]{4}-[]+ */
                    List<String> localVulnerabilityList=new ArrayList<>();
                    Pattern patternCVE =Pattern.compile("CVE-[0-9]{4}-[0-9]+");
                    Matcher mCVE=patternCVE.matcher(htmlLine);
                    if(mCVE.find()) {
                        hrefLineThreshold=0;
                        //String matchedCVE=mCVE.group(0).substring(0,mCVE.group(0).length()-1);// retrieving the '<'
                        localVulnerabilityList.add( mCVE.group(0) );
                        /**nextLine, while href to retrieve: match on href android.googlesource stg take it and save it   */
                        //brTest.readLine();
                        htmlLine = brTest.readLine();
                        htmlLine=htmlLine.replaceAll(".2F","\\/");
                        nbDebugLine+=1;
                        Pattern patternhref=Pattern.compile("href=\"https:\\/\\/android.googlesource.com(\\/[A-Za-z0-9]+)+\\/\\+\\/[a-z0-9]+");
                        Matcher mhref=patternhref.matcher(htmlLine);
                        boolean valueMatch=mhref.find();
                        exitTable=m.find();
                        while((valueMatch || hrefLineThreshold==0) && !exitTable){

                            if(valueMatch){
                                localVulnerabilityList.add(mhref.group(0).substring(6));
                                hrefLineThreshold=0;
                            }else{
                                hrefLineThreshold+=1;
                            }
                            htmlLine = brTest.readLine();// Skipping the line after a href for now, later TODO shall we get the A-[0-9]+ ref ? if yes, do
                            nbDebugLine+=1;
                            mhref=patternhref.matcher(htmlLine);
                            valueMatch=mhref.find();
                            m=pattern.matcher(htmlLine);
                            exitTable=m.find();
                        }

                    }
                    if (nbDebugLine>=1974) {
                     //   System.out.println(nbDebugLine);
                    }
                    if (localVulnerabilityList!= null && localVulnerabilityList.size()>1  ){
                        this.vulnerabilityList.add(localVulnerabilityList);
                    }
                    htmlLine = brTest.readLine();
                    nbDebugLine+=1;
                    /**     looking if we are out of the table */
                    if (!exitTable) {
                        m = pattern.matcher(htmlLine);
                        exitTable = m.find();
                    }
                }
            }
            htmlLine = brTest.readLine();
            nbDebugLine+=1;

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
     * substitues %F2 by /
     * param hrefLine: String
     * return String, the cleaned href line
     * throws
     */
    //private String cleanHref(String hrefLine){

    //}


    /**
     * testing the number of patch fetch in each monthly bulletin
     * param
     * return
     * throws
     */
    private void testFetchingURLs(String path) throws FileNotFoundException, IOException{
        this.path=path;
        vulnerabilityList= new ArrayList<>();
        updateReleasedBulletinsList();
        int[] counter=new int[releasedBulletins.size()];
        int totalRef=0;
        int[] buffCounter=new int[]{17,13,30,9,21,11,29,20,25,23,30,19,18,32,11,11,7,16,20,8,34,30,40,16,21,22,33,23,29,23,25,14,10,20,6,19,16,7,20};
        for (int i=0;i<buffCounter.length;i++){
            counter[i]=buffCounter[i];
            totalRef+=counter[i];
        }
        int testIndex=0;
        int counterOfMismatch=0;
        int totalMatch=0;

        //Under Work
        for (testIndex=0;testIndex<releasedBulletins.size();testIndex++){

            getPatchFromMonthly(releasedBulletins.get(testIndex));
            System.out.println("Unitary Test--bulletin "+testIndex+":  |"+this.vulnerabilityList.size()+"|"+counter[testIndex]+"|");
            if (this.vulnerabilityList.size()!=counter[testIndex]){
                System.out.println("---Potential error-Not corresponding to the reference number of bulletins released");
                counterOfMismatch+=1;
            }
            totalMatch+=this.vulnerabilityList.size();
            vulnerabilityList= new ArrayList<>();
        }

        System.out.println("TEST RESULTS: "+(releasedBulletins.size()-counterOfMismatch)+"/"+releasedBulletins.size()+"   ||   "+totalMatch+"/"+totalRef);


    }


    /**
     * param
     * return
     * throws
    */
    public static void main(String[] args) throws FileNotFoundException, IOException{
        String folderToDownloadIn= "/home/user1/Desktop/Tools/Vulnerabilities/test/listBulletins";
        BulletinImporter bImporter=new BulletinImporter(folderToDownloadIn);

        bImporter.testFetchingURLs(folderToDownloadIn);

    }
}

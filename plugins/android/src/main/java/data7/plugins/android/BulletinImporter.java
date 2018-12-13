package data7.plugins.android;


import data7.project.Project;
import miscUtils.Misc;
import org.eclipse.jgit.util.FileUtils;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.File;
import java.io.IOException;
import java.time.Year;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static data7.Utils.checkFolderDestination;
import static data7.Utils.deleteDir;

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

    //TODO to change for each device
    private  String localDLFolder= "/home/user1/Desktop/Tools/Vulnerabilities/test/tempoRepo2/listBulletins";

    /**
     *
     *
     *param path: String, toward which the file might be saved
     *return
     * throws
    */
    BulletinImporter(String path) throws IOException{
        this.path=path;
        vulnerabilityList= new ArrayList<>();
        int testIndex;
        List<String[]> upDateTable;
        List<String> dateList;

        checkForNewBulletin();
        upDateTable=loadReleasedBulletin(this.path);
        releasedBulletins=xEltsOfList(upDateTable, 0);
        dateList=xEltsOfList(upDateTable,1);

        for (testIndex=0;testIndex<releasedBulletins.size();testIndex++) {

            //if (testIndex==39)
            //    System.out.println("ola");


            getPatchFromMonthly(releasedBulletins.get(testIndex), dateList.get(testIndex));
            //System.out.println("Unitary Test--bulletin " + testIndex + ":  |" + this.vulnerabilityList.size() + "|");

        }
    }

    /**
     *Overcharging the constructor in case
     *
     *param of no path given
     *return
     * throws
     */
    BulletinImporter() throws IOException{
        this.path=localDLFolder;
        vulnerabilityList= new ArrayList<>();
        int testIndex;
        List<String[]> upDateTable;
        List<String> dateList;

        checkForNewBulletin();
        upDateTable=loadReleasedBulletin(this.path);
        releasedBulletins=xEltsOfList(upDateTable, 0);
        dateList=xEltsOfList(upDateTable,1);


        for (testIndex=0;testIndex<releasedBulletins.size();testIndex++) {

            //if (testIndex==39)
            //    System.out.println("ola");


            getPatchFromMonthly(releasedBulletins.get(testIndex), dateList.get(testIndex));
            //System.out.println("Unitary Test--bulletin " + testIndex + ":  |" + this.vulnerabilityList.size() + "|");

        }
    }



    /**
     *On th page of a monthly bulletin, this function is supposed to update the list of CVE retrieved : List<String,String> of <CVE, <patchURLName>>, not yet vulnerability but here it comes
     *
     *param String monthlyBulletinURL, the URL of one of the Android Bulletins
     *return
     * throws
     */
    private void getPatchFromMonthly (String monthlyBulletinURL, String upLastUpdate)throws IOException{
        int hrefLineThreshold=0;
        int rowspanThreshold=0;
        int nbDebugLine=0;
        //We will download using MiscUtils.Misc::downloadFromURL and then parse it to get the CVE and patch links */
        //Create Folder or check if exists*/
        String dlPath=this.path+"/Monthly/";
        checkFolderDestination(dlPath);
        //DownloadPage*/ if necessary
        //read the date at which the local file was changed for the last time in YYYYMMDD
        File monthlyHTML=new File(dlPath+"/"+monthlyBulletinURL.substring(45));
        if (monthlyHTML.exists()){

            Calendar lastUpdate=Calendar.getInstance();
            lastUpdate.setTimeInMillis(monthlyHTML.lastModified());
            //load the last time the bulletin was updated online

            //pass each to integer
            int localLastUpdateInt=Integer.valueOf( Integer.toString(lastUpdate.get(Calendar.YEAR))+Integer.toString(lastUpdate.get(Calendar.MONTH)+1)+Integer.toString(lastUpdate.get(Calendar.DAY_OF_MONTH)));
            int upLastUpdateInt=Integer.valueOf(upLastUpdate.replace("-",""));
            //compare
            if(upLastUpdateInt>localLastUpdateInt || upLastUpdateInt==0 || localLastUpdateInt==0){
                Misc.downloadFromURL((monthlyBulletinURL),dlPath);
            }

        }else{
            //Bulletin not yet downloaded
            Misc.downloadFromURL((monthlyBulletinURL),dlPath);
        }


        //Parse and store URLs of patches*/
        FileReader fReader=new FileReader( dlPath+"/"+monthlyBulletinURL.substring(45) );
        BufferedReader brTest = new BufferedReader(fReader);
        String htmlLine = brTest.readLine();
        nbDebugLine+=1;
        while (htmlLine!=null){
            //if Match on <table> */
            Pattern pattern=Pattern.compile("<table>");
            Matcher m=pattern.matcher(htmlLine);
            if (m.find()){
                // While no match on </table>, take nextLine on htmlLine */
                pattern=Pattern.compile("<\\/table>");
                m=pattern.matcher(htmlLine);
                boolean exitTable=m.find();
                while(!exitTable) {

                    //if match on CVE-[]{4}-[]+ */
                    List<String> localVulnerabilityList=new ArrayList<>();
                    Pattern patternCVE =Pattern.compile("CVE-[0-9]{4}-[0-9]+");
                    Matcher mCVE=patternCVE.matcher(htmlLine);
                    if(mCVE.find()) {
                        int trCounter=0;
                        //for the first versions (<=2016-04) of android bulletin all url are not retrieved
                        Pattern patternDate=Pattern.compile("[0-9]{4}-[0-9]{2}");
                        Matcher mDate=patternDate.matcher(monthlyBulletinURL);
                        mDate.find();
                        //String test=mDate.group(0).replaceAll("-","");
                        int date=Integer.parseInt(mDate.group(0).replaceAll("-",""));
                        if (date<=201604) {
                            Pattern patternMultiLineHref = Pattern.compile("rowspan=\"[0-9][0-9]?\"");
                            Matcher mMLHref = patternMultiLineHref.matcher(htmlLine);
                            if (mMLHref.find()) {
                                String nbLineRef = mMLHref.group(0).substring(9, mMLHref.group(0).length() - 1);
                                rowspanThreshold = Integer.parseInt(nbLineRef);
                            } else {
                                rowspanThreshold = 0;
                            }
                        }
                        //xxxx
                        hrefLineThreshold=0;
                        localVulnerabilityList.add( mCVE.group(0) );
                        //nextLine, while href to retrieve: match on href android.googlesource stg take it and save it   */
                        htmlLine = brTest.readLine();
                        htmlLine=htmlLine.replaceAll(".2F","\\/");
                        nbDebugLine+=1;
                        Pattern patternhref=Pattern.compile("href\\s?=\\s?\"(https:)?\\/\\/android.googlesource.com(\\/([A-Za-z0-9]+\\-?\\_?)+)+\\/\\+\\/[a-z0-9]+");
                        Matcher mhref=patternhref.matcher(htmlLine);
                        boolean valueMatch=mhref.find();
                        exitTable=m.find();
                        while((valueMatch || hrefLineThreshold==0 || trCounter<rowspanThreshold) && !exitTable ){
                            // </tr> counter between 2 CVEs
                            Pattern ptr=Pattern.compile("</tr>");
                            Matcher mtr=ptr.matcher(htmlLine);
                            if(mtr.find()){
                                trCounter+=1;
                            }
                            if(valueMatch){
                                localVulnerabilityList.add(mhref.group(0).substring(6));
                                while (mhref.find()){localVulnerabilityList.add(mhref.group(0).substring(6));}//have to let this line as a mhref.find has already been performed
                                hrefLineThreshold=0;
                            }else{
                                hrefLineThreshold+=1;
                            }
                            htmlLine = brTest.readLine();// Skipping the line after a href for now, later TODO shall we get the A-[0-9]+ ref ? if yes, do
                            htmlLine=htmlLine.replaceAll(".2F","\\/");
                            nbDebugLine+=1;
                            mhref=patternhref.matcher(htmlLine);
                            valueMatch=mhref.find();
                            m=pattern.matcher(htmlLine);
                            exitTable=m.find();
                        }

                    }
                    //if (nbDebugLine>=1025) {
                       //System.out.println(nbDebugLine);
                   // }
                    if (localVulnerabilityList!= null && localVulnerabilityList.size()>1  ){
                        this.vulnerabilityList.add(localVulnerabilityList);
                    }
                    htmlLine = brTest.readLine();
                    nbDebugLine+=1;
                    //     looking if we are out of the table */
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
        int yearCounter;// Starting year of the bulletins*/
        releasedBulletins=new ArrayList<>();
        for (yearCounter=2015;yearCounter<=currentYear;yearCounter++){
            indexURL=this.baseUrl+this.indexUrlPath+String.valueOf(yearCounter);

            //We will download using MiscUtils.Misc::downloadFromURL and then parse it to get the links of monthly androids bulletins */
            //Create Folder or check if exists*/
            checkFolderDestination(this.path);
            //DownloadPage*/
            Misc.downloadFromURL((indexURL),this.path);
            //Parse and store URLs of monthly bulletin*/
            FileReader fReader=new FileReader(path+"/"+String.valueOf(yearCounter) );
            BufferedReader brTest = new BufferedReader(fReader);
            String htmlLine = brTest.readLine();
            while (htmlLine!=null){
                Pattern pattern=Pattern.compile(regexpURL);
                Matcher m= pattern.matcher(htmlLine);
                if (m.find()){
                        String matchedURL=baseUrl+m.group(0).substring(0,m.group(0).length()-9);
                        //releasedBulletins.add(matchedURL);
                    //System.out.println("--DEBUGLINE--"+matchedURL);

                        int bulletinDate =extractDate(matchedURL);

                        //System.out.println("--DEBUGLINE--"+bulletinDate);

                        int bufferToRename=1;

                        while (bufferToRename <=releasedBulletins.size() ){
                            if ( bulletinDate > extractDate(releasedBulletins.get(releasedBulletins.size()-bufferToRename))){
                                releasedBulletins.add(releasedBulletins.size()-bufferToRename+1,matchedURL);
                                bufferToRename=releasedBulletins.size()+1;//get out of the loop in a non explicit way
                            }else{
                                if (releasedBulletins.size()==bufferToRename){
                                    releasedBulletins.add(0,matchedURL);
                                    bufferToRename=releasedBulletins.size();
                                }
                                bufferToRename+=1;
                            }

                        }
                        if(releasedBulletins.size()==0){
                            releasedBulletins.add(matchedURL);
                        }




             }
                htmlLine = brTest.readLine();
            }
            // ?? Suppress file ?? not if we want update mode later on


            brTest.close();
            fReader.close();
        }

    }

    /**
     * check for new bulletin and update list
     *
     *param
     *return
     * throws
     */
    private List<String[]> loadReleasedBulletin(String source) throws IOException {
        int currentYear=Year.now().getValue();
        List<String> localBulletins= new ArrayList<>();

        List<String> updateL=new ArrayList<>();

        for (int yearCounter=2015;yearCounter<=currentYear;yearCounter++) {
            String yearIndexLoc=source+"/"+Integer.toString(yearCounter);

            //prevent the case on the first bulletin of June by creating the file if it does not exist
            File f = new File(yearIndexLoc);
            if (!(f.exists() && f.isFile())) {
                f.createNewFile();
            }

            FileReader fReader = new FileReader(yearIndexLoc );
            BufferedReader brTest = new BufferedReader(fReader);
            String htmlLine = brTest.readLine();
            while (htmlLine!=null){
                //Find the monthly bulletin URL
                Pattern pattern=Pattern.compile(regexpURL);
                Matcher m= pattern.matcher(htmlLine);
                if (m.find()){
                    //Monthly URL found
                    String matchedURL=baseUrl+m.group(0).substring(0,m.group(0).length()-9);
                    //releasedBulletins.add(matchedURL);
                    //System.out.println("--DEBUGLINE--"+matchedURL);

                    int bulletinDate =extractDate(matchedURL);

                    //System.out.println("--DEBUGLINE--"+bulletinDate);

                    int bufferToRename=1;

                    while (bufferToRename <=localBulletins.size() ){
                        if ( bulletinDate > extractDate(localBulletins.get(localBulletins.size()-bufferToRename))){
                            localBulletins.add(localBulletins.size()-bufferToRename+1,matchedURL);
                            bufferToRename=localBulletins.size()+1;//get out of the loop in a non explicit way
                        }else{
                            if (localBulletins.size()==bufferToRename){
                                localBulletins.add(0,matchedURL);
                                bufferToRename=localBulletins.size();
                            }
                            bufferToRename+=1;
                        }
                    }
                    if(localBulletins.size()==0){
                        localBulletins.add(matchedURL);
                    }

                    int tdCounter=0;
                    Pattern tdPattern=Pattern.compile("</td>");
                    while(tdCounter!=2){
                        Matcher tdM= tdPattern.matcher(htmlLine);
                        if (tdM.find()){
                            tdCounter+=1;
                        }
                        else{
                            //nextline
                            htmlLine = brTest.readLine();
                        }
                    }
                    //The line does not contain a monthly bulletin URL so we will look for the last update ...date
                    Pattern updatePattern=Pattern.compile("20[0-9]{2}-[0-9]{2}-[0-9]{2}");
                    int updateMatched=0;
                    while (updateMatched==0) {
                        Matcher upDatem = updatePattern.matcher(htmlLine);
                        if (upDatem.find()) {
                            //We found a date in the right format but is it the latest for this bulletin ?
                            while (!htmlLine.contains("</td>")){
                                htmlLine = brTest.readLine();
                                upDatem = updatePattern.matcher(htmlLine);
                                upDatem.find();
                            }
                            //add it in the right position
                            int index=0;
                            if (updateL.size()>0) {
                                while (index < updateL.size() && Integer.valueOf(upDatem.group(0).replace("-", "")) > Integer.valueOf(updateL.get(index).replace("-", "")) ) {
                                    index++;
                                }
                                if(index==updateL.size() ){
                                    updateL.add(upDatem.group(0));
                                }else {
                                    updateL.add(index, upDatem.group(0));
                                }
                            }else{
                                updateL.add(upDatem.group(0));
                            }


                            //updateL.add(upDatem.group(0));
                            updateMatched = 1;
                        } else if (htmlLine.contains("N/A")) {
                            updateL.add(0,"0");
                            updateMatched = 1;
                        } else {
                            //nextline
                            htmlLine = brTest.readLine();
                        }
                    }
                }

                htmlLine = brTest.readLine();
            }
        }
        //Alter the list to fit in List<String[2]>
        //Where the first is the url and the second is the date of last update
        //can be extracted with xEltOfList(List<String[2], int)
        List<String[]> listToReturn=new ArrayList<>();
        int index;
        for (index=0;index<localBulletins.size();index++){
            String[] tempLine= new String[2];
            tempLine[0]=localBulletins.get(index);
            tempLine[1]=updateL.get(index);
            listToReturn.add(tempLine);
        }

        return listToReturn;
    }

    /**
     * check for new bulletin and update list in releasedBulletins
     *
     *param
     *return
     * throws
     */
    private void checkForNewBulletin() throws IOException{

        String dlPath=this.path+"/Monthly/";
        checkFolderDestination(dlPath);
        List<String> localBulletins= new ArrayList<>();
        int nbLocalBulletin=0, dlBulletin=0;
        int currentYear=Year.now().getValue();

        //get the number of downloaded Bulletin in this.path+"/Monthly/"
        localBulletins=xEltsOfList(loadReleasedBulletin(this.path),0);

        nbLocalBulletin=localBulletins.size();
        //get the number of online bulletins
            String repoName=this.path+"/temp";
            //create a tempo/buffer repo
             checkFolderDestination(repoName);
            //download
            int yearCounter;// Starting year of the bulletins*/

            for (yearCounter=2015;yearCounter<=currentYear;yearCounter++) {
                String indexURL = this.baseUrl + this.indexUrlPath + String.valueOf(yearCounter);
                checkFolderDestination(repoName);
            //DownloadPage
                Misc.downloadFromURL((indexURL),repoName);
             }
            //loadNumber
            dlBulletin=loadReleasedBulletin(repoName).size();
            //delete the repo
            deleteDir(repoName);

        //Compare
        if (nbLocalBulletin==dlBulletin){
            //everything alright
            System.out.println("No need for update");
        }else if(nbLocalBulletin<dlBulletin){
            //upload and save the saved bulletins
            updateReleasedBulletinsList();
            System.out.println("Update done");
        }else {
            //warn of problem
        }
    }

    /**
     * In order to order Bulletin because google mixes the way they are ordered
     *
     *param
     *return
     * throws
     */
    private int extractDate(String matchedURL){
        String regexDate= "[0-9]{4}-[0-9]{2}-[0-9]{2}";
        Pattern patternDate=Pattern.compile(regexDate);
        Matcher matcherDate= patternDate.matcher(matchedURL);
        matcherDate.find();
        return Integer.parseInt(matcherDate.group(0).replaceAll("-",""));

    }

    /**
     * param the vulnerability extracted from a bulletin List<String> as [CVE, patchURL1, patchURL2,...]
     *return List<String> as <componentPatch1,componentPatch2,...>
     * throws
     */
    public List<String> getVulnerabilityComponents(List<String> bulletinVulnerability){
        List<String> componentList=new ArrayList<>();
        Iterator<String> compoIterator=bulletinVulnerability.iterator();
        Pattern componentPattern= Pattern.compile("(\\/([A-Za-z0-9]+\\-?\\_?)+)+\\/\\+");
        //Skipping first element
        compoIterator.next();
        String patchURL=compoIterator.next();
        String matched;
        while (patchURL!=null) {
            Matcher componentMatcher = componentPattern.matcher(patchURL);
            //TODO remove condition
            if (componentMatcher.find()) {
                matched = componentMatcher.group(0);
                matched = matched.substring(1, matched.length() - 2);
                componentList.add(matched);
            }
            if (compoIterator.hasNext()){
                patchURL=compoIterator.next();
            }else{
                patchURL=null;
            }

        }
        return componentList;

    }

    /**
     * param the URL of the commit as a string
     *return the extracted hash of the commit
     * throws
     */
    public String getComponent(String URL){
        Pattern componentPattern= Pattern.compile("(\\/([A-Za-z0-9]+\\-?\\_?)+)+\\/\\+\\/.+");
        //Skipping first element
        String matched=null ,component=null ;

        Matcher componentMatcher = componentPattern.matcher(URL);
        //TODO remove condition
        if (componentMatcher.find()) {
            matched = componentMatcher.group(0);
            Pattern compoPattern=Pattern.compile("(\\/([A-Za-z0-9]+\\-?\\_?)+)+");
            Matcher compoM = compoPattern.matcher(matched);
            if (compoM.find()){
                component=compoM.group(0).substring(1);
            }
        }
        return component;
    }



    /**
     * param the URL of the commit as a string
     *return the extracted hash of the commit
     * throws
     */
    public String getCommitHash(String URL){
        Pattern componentPattern= Pattern.compile("(\\/([A-Za-z0-9]+\\-?\\_?)+)+\\/\\+\\/.+");
        //Skipping first element
        String matched=null ,hash=null ;

        Matcher componentMatcher = componentPattern.matcher(URL);
        //TODO remove condition
        if (componentMatcher.find()) {
            matched = componentMatcher.group(0);
            Pattern hashPattern=Pattern.compile("\\/\\+\\/.+");
            Matcher hashM = hashPattern.matcher(matched);
            if (hashM.find()){
                hash=hashM.group(0).substring(3);
            }
        }



        return hash;

    }

    /**
     *
     * params
     * return Hsahmap for which the number of  vulnerability components (/location) is linked to the name of the component
     * throws
     */
    private HashMap<String, Integer> byComponentCounter(){
        HashMap<String, Integer> countingTable=new HashMap<String, Integer>();
        List<String> returnedComponentsByCVE=new ArrayList<>();
        int matchedInList=0;
        //for all in this.vulnerabilityList
        for (List<String> cveList  :vulnerabilityList ) {
            returnedComponentsByCVE=getVulnerabilityComponents(cveList);
            for (int j=0; j<returnedComponentsByCVE.size();j++) {
                matchedInList = 0;
                //try to match in the local arrayList.get(0)
                //if works/get(1) then counter+=1
                if ( countingTable.containsKey(returnedComponentsByCVE.get(j))) {
                    countingTable.replace(returnedComponentsByCVE.get(j),countingTable.get(returnedComponentsByCVE.get(j)),countingTable.get(returnedComponentsByCVE.get(j))+1);
                    matchedInList = 1;
                }
                //if matchedInList ==0 out of loop then add to local list and add+=1
                if (matchedInList==0){
                    countingTable.put(returnedComponentsByCVE.get(j),1);
                }
            }
        }
        return countingTable;
    }

    /**
     *
     * params
     * return HashMap for which the number of  vulnerability components (/location) is linked to the name of the component
     * throws
     */
    private HashMap<String, List<String>>  byComponentSorter(){
        HashMap<String, List<String>> sortedByLocCVEs=new HashMap<>();
        for (List<String>  singleVulnerability: this.vulnerabilityList){
            for (int i=0;i<getVulnerabilityComponents(singleVulnerability).size();i++){
                //if the vulnerabilityComponent is already listed, we will add the cve to the list
                String test=getVulnerabilityComponents(singleVulnerability).get(i);
                if (sortedByLocCVEs.containsKey(getVulnerabilityComponents(singleVulnerability).get(i))) {
                    //System.out.println("--DEBUG--"+getVulnerabilityComponents(singleVulnerability).get(i)+"_is_included_in_the file");
                    sortedByLocCVEs.get(getVulnerabilityComponents(singleVulnerability).get(i)).add(singleVulnerability.get(0));
                }
                else{
                    List<String> bufferLocCVE=new ArrayList<>();
                    bufferLocCVE.add( singleVulnerability.get(0));
                    sortedByLocCVEs.put(getVulnerabilityComponents(singleVulnerability).get(i),  bufferLocCVE );
                }
            }
        }
        return sortedByLocCVEs;
    }

    /**
     *
     * params
     * return HashMap for which the number of  vulnerability components (/location) is linked to the name of the component
     * throws
     */
    public Map<String, Map<String, List<String>>>  cveCompHashSorter(){
        Map<String, Map<String, List<String>>> sortedByCVEs=new HashMap<>();
        Map<String, List<String>> mergedOnCVEMap =new HashMap<>();

        mergedOnCVEMap=mergeOnKey(vulnerabilityList);

        //for each CVE, split the URLs into <component,<hashes>>
        mergedOnCVEMap.forEach((CVE, listOfURL) ->{
            Map<String, List<String>> mergedOnComponentMap =new HashMap<>();
            List<List<String>> listBeforeMerge=new ArrayList<>();

            listOfURL.forEach(( url) ->{
                //from List<String> to List<List<String>> wih split component ,hash
                List<String> splitCompHash= new ArrayList<>();
                splitCompHash.add(getComponent(url));
                splitCompHash.add(getCommitHash(url));
                listBeforeMerge.add(splitCompHash);
            });
            //merge if any CVE has the same component several time
            mergedOnComponentMap=mergeOnKey(listBeforeMerge);
            sortedByCVEs.put(CVE,mergedOnComponentMap);
        });

        return sortedByCVEs;
    }

    /**
     *
     * params
     * return HashMap for which the number of  vulnerability components (/location) is linked to the name of the component
     * throws
     */
    public Map<String, List<String>> mergeOnKey(List<List<String>> listToRefactor ){
        Map<String, List<String>> refactoredMap=new HashMap<>();


        int listExplorer1=0, listExplorer2=0;
        List<Integer> exclusionList=new ArrayList<>();
        int matchURLExplorer;
        Map<String, List<String>> bufCompoHashes=new HashMap<>();//will store <CVE,<URLs>>
        //look for each entry/CVE/vulnerability
        for (listExplorer1=0; listExplorer1<listToRefactor.size();listExplorer1++){
            List<String> urlList=new ArrayList<>();
            //skipp the already merged entries
            if (!exclusionList.contains(listExplorer1)){

                //add  the urls linked with this CVE/vulnerability inside bufCompoHash
                for (matchURLExplorer=1;matchURLExplorer<listToRefactor.get(listExplorer1).size();matchURLExplorer++){
                    urlList.add(listToRefactor.get(listExplorer1).get(matchURLExplorer));
                }

                for (listExplorer2=listExplorer1+1; listExplorer2<listToRefactor.size();listExplorer2++) {
                    //check for CVE equality
                    if (listToRefactor.get(listExplorer1).get(0).equals( listToRefactor.get(listExplorer2).get(0))) {
                        //to prevent listExplorer1 from passing by listExplorer2 if there is a match
                        exclusionList.add(listExplorer2);

                        //vulnerabilityList is a List<List<String>> starting by CVE, then urls related
                        for (matchURLExplorer=1;matchURLExplorer<listToRefactor.get(listExplorer2).size();matchURLExplorer++){
                            //add the urls to vulnerabilityList.get(listExplorer1)'s url list
                            urlList.add(listToRefactor.get(listExplorer2).get(matchURLExplorer));
                        }
                    }
                }
                refactoredMap.put(listToRefactor.get(listExplorer1).get(0), urlList);
            }
            //then add the resulting CVE,<URLs> to sortedByCVEs
        }
        return refactoredMap;
    }

    /**
     *
     * params
     * return HashMap for which the number of  vulnerability components (/location) is linked to the name of the component
     * throws
     */
    public List<String> xEltsOfList(List<String[]> listToSplit, int refElt){
        List<String> extractedList=new ArrayList<>();
        int index=0;
        for (index=0;index<listToSplit.size();index++){
            extractedList.add((listToSplit.get(index))[refElt]);
        }



        return extractedList;
    }


    /**
     * testing the number of patch fetch in each monthly bulletin
     * param
     * return
     * throws
     */
    private void testFetchingURLs(String path) throws IOException{
        this.path=path;
        vulnerabilityList= new ArrayList<>();
        List<String[]> upDateTable;
        List<String> dateList;
        updateReleasedBulletinsList();
        int[] counter=new int[releasedBulletins.size()];
        int totalRef=0;
        //number of cve referenced per page
        int[] buffCounter=new int[]{21,8,29,7,17,7,11,11,32,18,19,30,23,25,20,29,11,29,23,33,22,21,16,40,30,34,8,20,16,20,7,16,19,6,20,10,14,25,23,19};
        for (int i=0;i<buffCounter.length;i++){
            counter[i]=buffCounter[i];
            totalRef+=counter[i];
        }
        int testIndex=0;
        int counterOfMismatch=0;
        int totalMatch=0;

        checkForNewBulletin();
        upDateTable=loadReleasedBulletin(this.path);
        releasedBulletins=xEltsOfList(upDateTable, 0);
        dateList=xEltsOfList(upDateTable,1);
        //Get patches and check number
        for (testIndex=0;testIndex<releasedBulletins.size();testIndex++){

            getPatchFromMonthly(releasedBulletins.get(testIndex),dateList.get(testIndex));
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
     * testing the fetching of components
     * params
     * return
     * throws
     */
    private void testFetchingComponents(){
        for (int cveCounter=0;cveCounter<this.vulnerabilityList.size();cveCounter++) {
            List<String> oneCVEComponents = new ArrayList<>(getVulnerabilityComponents(this.vulnerabilityList.get(cveCounter)));
            for (int i = 0; i < oneCVEComponents.size(); i++) {
                System.out.println("Component "+cveCounter+"-"+oneCVEComponents.get(i));

            }
            if (cveCounter==222){System.out.println("Here we are");}
        }
    }

    /**
     * testing count of components
     * params
     * return
     * throws
     */
    private void testComponentsCounter(){
        HashMap<String, Integer> mp=byComponentCounter();
        Iterator it = mp.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            System.out.println(pair.getValue() + "    ---    " + pair.getKey());
            it.remove(); // avoids a ConcurrentModificationException
        }
    }

    /**
     * testing the sorting of components
     * params
     * return
     * throws
     */
    private void testComponentsSorter(){
        HashMap<String, List<String>> mp=byComponentSorter();
        Iterator it = mp.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            System.out.println(pair.getKey() + "\n"+pair.getValue().toString());
            //for (int j=0;j<pair.getValue().size();j++){
            //    System.out.println("    ---    "+ pair.getValue().get(j));
            //}
            it.remove(); // avoids a ConcurrentModificationException
        }
    }

    /**
     * testing the sorting of components
     * params
     * return
     * throws
     */
    private List<List<String>> getVulnerabilityList(){
        return vulnerabilityList;
    }

    /**
     * param
     * return
     * throws
    */
    public static void main(String[] args) throws IOException{
        //String folderToDownloadIn= "/home/user1/Desktop/Tools/Vulnerabilities/test/listBulletins";

        BulletinImporter bImporter=new BulletinImporter();



        // List of Tests
        //bImporter.testFetchingURLs(folderToDownloadIn);
        //bImporter.getVulnerabilityComponents((bImporter.vulnerabilityList).get(6));
        //bImporter.testFetchingComponents();
        //bImporter.testComponentsCounter();
        //bImporter.testComponentsSorter();
        //bImporter.getCommitHash(bImporter.getVulnerabilityList().get(0).get(1));
        bImporter.cveCompHashSorter();
    }
}

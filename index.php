<?php

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// variables
// /////////////////////////////////////////////////////////////////////////////////////////////////////

// this script parses PCI-DSS pdf->html conversion into requirement objects
$allDivs = array();
$reqObjects = array();

// html divs are sorted into these columns
$columns = [
    [], // ID (to be parsed)
    [], // Requirement
    [], // Testing
    [], // Guidance
    [] // text not in PCI-DSS table
];

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// dir with pdf files
// /////////////////////////////////////////////////////////////////////////////////////////////////////

$dirName = "pages-all-reqs";

$dir = array_diff(scandir($dirName), array(
    '..',
    '.'
));

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// process dir: each PCI-DSS page is an html file in the dir
// /////////////////////////////////////////////////////////////////////////////////////////////////////

foreach ($dir as $file) {

    $pageDivs = array();

    $lineNum = 0;
    $file = "$dirName/$file";
    $page = fopen($file, "r");
    $pageNum = str_replace("pages/page", "", $file);
    $pageNum = str_replace(".html", "", $pageNum);

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // isolate and save each div tag with properties as "div" object
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    while (! feof($page)) {

        $line = fgets($page);

        $isDiv = substr($line, 0, 4);

        if ($isDiv == "<div") {

            $lineObj = new Div();

            $spanCount = substr_count($line, "/span");

            $lineText = $line;

            $spanPattern = "/[^>]+<\/span>/";

            $lineText = preg_match_all($spanPattern, $line, $spanMatches);

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // 1 span get and set line text
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            if ($lineText && $spanCount == 1)
                $lineText = $spanMatches[0][0];

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // combine multiple spans
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            if ($spanCount > 1) {

                $lineText = "";
                $spans = count($spanMatches[0]);

                for ($span = 0; $span < $spans; $span ++) {

                    $lineText = $lineText . $spanMatches[0][$span];
                }
            }

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // clean up line text
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            $lineText = str_replace("</span>", "", $lineText);

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // get and set line details (left and top) for column and paragraph
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            if (isset($top)) {
                $lastTop[$col] = $top;
                $lastCol = $col;
            }

            $top = preg_match("/top:\d+px/", $line, $topMatches);
            $top = preg_match("/\d+/", $topMatches[0], $topMatches);
            $left = preg_match("/left:\d+px/", $line, $leftMatches);
            $left = preg_match("/\d+/", $leftMatches[0], $leftMatches);
            $font = preg_match("/font-size:\d+px/", $line, $fontMatches);
            $font = (int) preg_match("/\d+/", $fontMatches[0], $fontMatches);
            $top = (int) $topMatches[0];
            $left = (int) $leftMatches[0];
            $font = (int) $fontMatches[0];

            $col = match ($left) {
                76, 72, 77, 78, 80, 81, 83, 92, 95, 98, 59, 74, 106, 94, 62, 73, 89, 58, 71, 103, 117, 90, 96, 112, 99, 75, 114, 100, 157, 91 => 1,
                298, 301, 312, 300, 315, 297, 284, 290, 310, 314 => 2,
                514, 527, 528, 517, 535, 513, 512, 500, 535, 511, 525, 516, 531 => 3,
                default => 4
            };

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // make line object
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            $lineObj->spans = $spanCount;
            $lineObj->font = $font;
            $lineObj->top = $top;
            $lineObj->left = $left;
            $lineObj->col = $col;
            $lineObj->lineText = $lineText;
            $lineObj->line = $line;

            // /////////////////////////////////////////////////////////////////////////////////////////////////////
            // skip boilerplate lines
            // /////////////////////////////////////////////////////////////////////////////////////////////////////

            $skip = false;

            $skipArray = [
                "Guidance",
                "Requirements and Testing Procedures",
                "Payment Card Industry Data Security Standard: Requirements and Testing Procedures, v4.0.1",
                "June 2024",
                "©2006 - 2024 PCI Security Standards Council, LLC. All Rights Reserved.",
                "© 2006 - 2024 PCI Security Standards Council, LLC. All rights reserved."
            ];

            $skipArray = array_combine(array_keys(array_fill(1, count($skipArray), 0)), array_values($skipArray));
            $skipPattern = "/^Page \d+$/";

            if (preg_match($skipPattern, $lineText) || array_search($lineText, $skipArray))
                $skip = TRUE;
            if (! $skip)
                array_push($pageDivs, $lineObj);
        }
        // end of page line
        $lineNum ++;
    }

    // sort divs by height per page
    usort($pageDivs, 'comparator');
    $allDivs = array_merge($allDivs, $pageDivs);

    // end of page
    fclose($page);
}

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// clean up old vars
// /////////////////////////////////////////////////////////////////////////////////////////////////////

$vars = array_keys(get_defined_vars());
foreach ($vars as $var) {

    $skip = FALSE;

    if ($var == "allDivs" || $var == "reqObjects")
        $skip = TRUE;

    if (! $skip)
        unset(${"$var"});
}

unset($skip, $vars, $var);

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// process divs
// /////////////////////////////////////////////////////////////////////////////////////////////////////

$sections = FALSE;
$overview = FALSE;
$appIntro = FALSE;

for ($divNum = 0; $divNum < count($allDivs); $divNum ++) {

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // get line info
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    $lineObj = $allDivs[$divNum];

    $lineText = $lineObj->lineText;
    $spanCount = $lineObj->spans;
    $top = $lineObj->top;
    $left = $lineObj->left;
    $col = $lineObj->col;
    $font = $lineObj->font;

    if (isset($lastTops[$col]))
        $lastTop = $lastTops[$col];
    else
        unset($lastTop);

    $lastTops[$col] = $top;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // get and set categories
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    if ($font == 14)
        $cat = $lineText;

    $a1 = $a2 = $a3 = FALSE;

    if ($font == 12) {
        if (str_starts_with($lineText, "Appendix A1")) {
            $a1 = TRUE;
            $appIntro = FALSE;
        }
        if (str_starts_with($lineText, "Appendix A2"))
            $a2 = TRUE;
        if (str_starts_with($lineText, "Appendix A3"))
            $a3 = TRUE;
    }

    if (isset($req)) {
        if ($a1)
            $cat = "Appendix A1";
        if ($a2)
            $cat = "Appendix A2";
        if ($a3)
            $cat = "Appendix A3";
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // Requirement N
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    $nReq = preg_match("/^Requirement \d+:/", $lineText);
    $anReq = preg_match("/^Appendix A\d+:/", $lineText);

    if ($nReq || $anReq) {

        $isN = TRUE;

        // first requirement
        if (! isset($req))
            $req = new Requirement();

        // new N so save current requirement
        else {
            saveReq($req);
            $req = new Requirement();
        }

        // set Parent N for subsequent N.Ns
        $colon = strpos($lineText, ":");
        $reqN = substr($lineText, $colon + 2);
        $parentN = $reqN;

        // make N req
        $req->req = $lineText;

        $guidance = emphasis("Category") . "<br><br>$cat<br><br>";

        $req->guidance = $guidance;
    }

    // multi-line N or A
    if (isset($req) && $font == 12)

        if ($req->req == $lineText);
        else
            $req->req = $req->req . " " . $lineText;

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // Requirement N.N
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    $nnPattern = "/^\d+.\d+ /";
    $annPattern = "/^A\d+.\d+ /";

    if ($spanCount == 1 && $col == 1) {

        $nnReq = preg_match($nnPattern, $lineText);
        $annReq = preg_match($annPattern, $lineText);
    }

    if ($nnReq || $annReq) {

        $overview = FALSE;
        $isN = FALSE;
        $isNN = TRUE;

        saveReq($req);
        $req = new Requirement();

        $guidance = emphasis("Category") . "<br><br>$cat<br><br>" . emphasis("Parent Requirement") . "<br><br>$parentN";

        $req->guidance = $guidance;
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // paragraphs
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    if (isset($lastTop))
        $vSpace = $top - $lastTop;
    if (isset($vSpace)) {
        $lineText = paragraph($lineText, $vSpace);
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // skip "Sections" and add "Overview" to N and A guidance
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    if ($lineText == "Sections" && $col == 4) {
        $sections = TRUE;
    }

    if ($lineText == "Overview" || $lineText == "<b>Overview</b>" || $lineText == "<u>Overview</u>" && $col == 4) {
        $sections = FALSE;
        $overview = TRUE;
    }

    if ($lineText == "Appendix A Additional PCI DSS Requirements") {
        $appIntro = TRUE;
    }

    while ($overview) {
        if (isset($req))
            $req->guidance = $req->guidance . " $lineText";
        break;
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // Requirement N.N.N
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    if (str_contains($lineText, "Defined Approach Requirements")) {

        $isN = FALSE;
        $isNN = FALSE;

        saveReq($req);

        $req = new Requirement();
    }

    // /////////////////////////////////////////////////////////////////////////////////////////////////////
    // if requirement is open add lines
    // /////////////////////////////////////////////////////////////////////////////////////////////////////

    if (isset($req)) {

        switch ($col) {

            case 1:

                // skip some lines (N and A already have multi-line based on font == 12)
                if (! $isN && ! $sections && ! $appIntro)
                    // don't add space to new paragraph
                    if (str_starts_with($lineText, "<br>"))
                        $req->req = trim($req->req . $lineText);
                    else
                        $req->req = trim($req->req . " " . $lineText);
                break;

            case 2:

                if (str_starts_with($lineText, "<br>"))
                    $req->test = trim($req->test . $lineText);
                else
                    $req->test = trim($req->test . " " . $lineText);
                break;

            case 3:

                if (str_starts_with($lineText, "<br>"))
                    $req->guidance = trim($req->guidance . $lineText);
                else
                    $req->guidance = trim($req->guidance . " " . $lineText);
                break;

            default:
                ;
                break;
        }
    }
}

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// last requirement needs ID and array pushing
// /////////////////////////////////////////////////////////////////////////////////////////////////////

saveReq($req);

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// draw html table of objects
// /////////////////////////////////////////////////////////////////////////////////////////////////////

echo table($reqObjects);

// /////////////////////////////////////////////////////////////////////////////////////////////////////
// objects and functions
// /////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Short description for class
 *
 * Long description for class (if any)...
 *
 * @copyright 2006 Zend Technologies
 * @license http://www.zend.com/license/3_0.txt PHP License 3.0
 * @version Release: @package_version@
 * @link http://dev.zend.com/package/PackageName
 * @since Class available since Release 1.2.0
 */
class Div
{

    public $spans;

    public $font;

    public $top;

    public $left;

    public $col;

    public $lineText;

    public $line;
}

/**
 *
 * @author s
 *        
 */
class Requirement
{

    public $id;

    public $req;

    public $test;

    public $guidance;
}

/**
 *
 * @param unknown $req
 */
function saveReq($req)
{
    global $reqObjects;

    $reqText = $req->req;

    $space = strpos($reqText, " ");
    $colon = strpos($reqText, ":");

    $sub = substr($reqText, 0, $space);

    if ($sub == "Appendix")
        $req->id = substr($reqText, $space + 1, $colon - $space - 1);

    if ($sub == "Requirement")
        $req->id = substr($reqText, $space + 1, $colon - $space - 1);

    $nnPattern = "/^\d+.\d+ /";
    $isNN = preg_match($nnPattern, $reqText, $nnMatch);

    if ($isNN)
        $req->id = trim($nnMatch[0]);

    $nnnPattern = "/<br><br>\d+.\d+[.\d+]+ /";
    $isNNN = preg_match($nnnPattern, $reqText, $nnnMatch);

    if ($isNNN)
        $req->id = str_replace("<br><br>", "", trim($nnnMatch[0]));

    $annPattern = "/^A\d+.\d+ /";
    $isANN = preg_match($annPattern, $reqText, $annMatch);

    if ($isANN)
        $req->id = trim($annMatch[0]);

    $annnPattern = "/<br><br>A\d+.\d+[.\d+]+ /";
    $isANNN = preg_match($annnPattern, $reqText, $annnMatch);

    if ($isANNN)
        $req->id = str_replace("<br><br>", "", trim($annnMatch[0]));

    if ($req->id == "")
        echo "";

    array_push($reqObjects, $req);
}

// lines will be sorted by height per page
function comparator($object1, $object2)
{
    return $object1->top <=> $object2->top;
}

// use vertical space and header text to insert <br> as appropriate
// could be used to bold / underline headers
function paragraph($lineText, $vSpace)
{
    global $isNN;
    $newPara = FALSE;
    $notHead = FALSE;
    global $isNN;

    $paraArray = [
        10,
        11,
        12,
        13
    ];

    $newPara = (! in_array($vSpace, $paraArray));

    $headArray = [
        "Defined Approach Requirements",
        "Defined Approach Testing Procedures",
        "Purpose",
        "Overview"
    ];

    $notHead = (! in_array($lineText, $headArray));

    $boldArray = [
        "Good Practice",
        "Definitions",
        "Examples",
        "Further Information",
        "Parent Requirement",
        "Customized Approach Objective"
    ];

    $toBold = (in_array($lineText, $headArray) || in_array($lineText, $boldArray));

    // bolding doesn't work with Google Sheets
    // <br> doesn't work with Excel
    // both work with Excel online and browser table render

    // changing tags can break parsing (e.g. overview)

    if ($toBold)
        $lineText = emphasis($lineText);

    if ($newPara && $notHead & ! $isNN) {

        return "<br><br>$lineText";
    } else

        return $lineText;
}

/**
 * Create an HTML table
 *
 * @param array $reqObjects
 *            Requirement objects
 *            
 * @throws Some_Exception_Class If something interesting cannot happen
 * @author saocode
 * @return A table
 */
function table($reqObjects)
{
    $table = <<< EOT
    <style>
    .tb {
    border-collapse: collapse;
    }
    .tb th, .tb td {
    vertical-align: top;
    font-family: Arial, Helvetica, sans-serif;
    font-size:14px;
    padding: 5px;
    border: solid 1px teal;
    }
    .tb th {
    background-color: teal;
    color:white;
    text-align:left;
    }
    </style>
    <html>
    <body>
    <table class="tb">
    <tr>
    <th>ID</th>
    <th>Requirement</th>
    <th>Testing</th>
    <th>Guidance</th>
    </tr>
    EOT;

    foreach ($reqObjects as $req) {

        $table .= <<< EOT
        <tr>
        <td>$req->id</td>
        <td>$req->req</td>
        <td>$req->test</td>
        <td>$req->guidance</td>
        </tr>
        EOT;
    }

    $table .= <<< EOT
    </table>
    </body>
    </html>
    EOT;

    return $table;
}

function emphasis($lineText)
{
    $tag = FALSE;
    
    // comment next line for no emphasis
    $tag = "b";
    
    if ($tag != FALSE)
        return "<$tag>$lineText</$tag>";
    else
        return $lineText;
}
    
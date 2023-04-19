rule M_Downloader_GOOTLOADER_POWERSHELL

{

  meta:

    author = "Mandiant"

    description = "Hunting rule looking for GOOTLOADER.POWERSHELL samples."

    md5 = "2567a2bca964504709820de7052d3486"

 

  strings:

    $ps_object_a = ".IsLink" ascii

    $ps_object_b = ".IsFolder" ascii

    $ps_object_c = ".IsFileSystem" ascii

   

    $ps_code_parseresponse = "[1] -replace" ascii nocase

    $ps_code_httpheader = ".Headers.Add(\"Cookie:" ascii nocase

    $ps_code_concatenatedata = "([String]::Join(\"|" ascii nocase

 

  condition:

    all of ($ps_code_*) and any of ($ps_object_*)

}

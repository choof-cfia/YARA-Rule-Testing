rule M_Launcher_FONELAUNCH_3

{

    meta:

      author = “Mandiant”

      description = “Hunting rule looking for FONELAUNCH.PHONE samples.”

      md5 = "ec17564ac3e10530f11a455a475f9763"

 

    strings:

      $str_winfunction = "LoadLibrary" ascii

      $str_registrykey = "SOFTWARE\\" wide

      $str_constant = "PAGE_EXECUTE_READWRITE" ascii

 

      $ilasmx86_sequence_encoding_a = { 0A 06 02 7D [3] 04 00 16 06 }

      $ilasmx86_sequence_encoding_b = { 72 [3] 70 72 [3] 70 6F ?? 00 00 0A }

 

    condition:

      uint16(0) == 0x5A4D and all of ($str_*) and

      (

        $ilasmx86_sequence_encoding_a and #ilasmx86_sequence_encoding_b >= 16

      )

}
BEGIN { skipit=0 }
function printdef(sym)
{
  if(skipit == 0) 
   printf "dict_addint(dict, revdict, \"%s\", %s);\n", sym, sym;
}

#/^ *(ec|error_code)[[:blank:]]+[[:upper:][:digit:]_]+[[:blank:]]*,/ { printdef(substr($2, 0, length($2)-1)) }
/^#if 0/ { skipit++; }
/^#endif/ { if(skipit > 0) skipit--; }
/^#define[[:blank:]]+(HAVE_|SIZEOF_|KRB5PLACEHOLD_|FALSE|TRUE)/ {next;}
/^#define[[:blank:]]+[[:upper:][:digit:]_]+[[:blank:]]+(\(?(\(krb5_msgtype\))?[[:xdigit:]\-x]+\)?|[[:upper:][:digit:]_]+)[[:blank:]]?.*$/ { printdef($2); }

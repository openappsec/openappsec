export param="$2"
export label="$5"
export version="$7"
export script="$8"

echo $6 | sed 's/ARGPACKINGMAGIC/\n/g' | awk -v cmd=$1 -v dir=$3 -v artifact=$4 '
{
  offset = index($0,"ARGSPACEMAGIC");
  space="";
  while(offset + length(space) < 40) space = space " ";
  gsub(/ARGSPACEMAGIC/,space,$0);
  if(length($0)) help = help "\\n" $0
}
END {
  gsub(/\\ /, " ", help);
  system(cmd" -q "ENVIRON["param"]" "dir" "artifact " \"" ENVIRON["label"] "\" \"" help "\" \"" ENVIRON["version"] "\" " ENVIRON["script"]);
}'

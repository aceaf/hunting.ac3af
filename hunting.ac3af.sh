#!/bin/bash

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Save starting execution time
start=`date +%s`

echo ''
echo 'ac3af - Bug Hunting Recon Automation Script'
echo ''

read -p "Enter the target domain: " target

# Save file of tools
subdomains_file="Target_Subdomains.txt"
out_of_scope_targets="Out_Of_Scope_Targets.txt"
sorted_subdomains_file="Sorted_Target_Subdomains.txt"
valid_subdomains_file="Valid_Target_Subdomains.txt"
subdomains_file_403="403_Target_Subdomains.txt"
target_links_file="Target_Links.txt"
paramspider_urls="Parmaspider_Urls_Findings.txt"
katana_urls="Katana_Urls_Findings.txt"
sorted_links_file="Sorted_Target_Links.txt"
file_type="Filetype_Links.txt"
endpoint_parameter_file="Target_Endpoint_Parameter.txt"
type_bugs_file="Filetype_Bugs.txt"
parameter_kxss_file="Target_Endpoint_Parameter_Kxss.txt"
cves_bugs="CVEs_Vulnerabilites.txt"

echo ''
echo "Running subdomain enumeration..."
subfinder -d "$target" -silent -o "$subdomains_file"
findomain -t "$target" --quiet | tee -a "$subdomains_file"
chaos -d "$target" -key Cvz4DMfTkkd3PRX0VoYDjoLnp3G5LUGbnmKSlIuhY2Re3sGxPj6rT1SF17F3ulB7 -silent | tee -a "$subdomains_file"
assetfinder --subs-only "$target" | tee -a "$subdomains_file"
echo "Subdomain enumeration completed."
echo ''

# Ask the user for out-of-scope targets
read -p "Enter comma-separated out-of-scope domains: " out_of_scope_domains

IFS=',' read -ra out_of_scope_array <<< "$out_of_scope_domains"

# Check if the target is out of scope
for out_of_scope_domain in "${out_of_scope_array[@]}"; do
    if [[ "$target" == "$out_of_scope_domain" ]]; then
        echo "$target is out of scope for this testing." >> "$out_of_scope_targets"
        exit 1
    fi
done

echo ''
echo "Sorting subdomains..."
sort -u "$subdomains_file" -o "$sorted_subdomains_file"

# Remove out-of-scope targets from further scanning
for out_of_scope_domain in "${out_of_scope_array[@]}"; do
    sed -i "/$out_of_scope_domain/d" "$sorted_subdomains_file"
done

# Explicitly append out-of-scope targets to the text file
for out_of_scope_domain in "${out_of_scope_array[@]}"; do
    echo "$out_of_scope_domain is out of scope for this testing." >> "$out_of_scope_targets"
done

echo "Subdomains sorted."

echo ''
echo "Validating subdomains and Sorting 403_subdomains..."
cat "$sorted_subdomains_file" | httpx  -silent | tee -a "$valid_subdomains_file"
# Check if there are 403 subdomains
if [ -s "$sorted_subdomains_file" ]; then
    cat "$sorted_subdomains_file" | httpx -mc 403 -silent | tee -a "$subdomains_file_403"
else
    echo "No subdomains found with 403 response."
fi

# Check if subdomains file 403 is empty and remove it if necessary
if [ ! -s "$subdomains_file_403" ]; then
    echo "Removing empty subdomains file 403."
    rm "$subdomains_file_403"
fi

echo ''
echo "Obtaining links..."
cat "$valid_subdomains_file" | getallurls > "$target_links_file"
echo "Links obtained."

echo ''
echo "Running ParamSpider on main domain..."
# Get params with ParamSpider from target
paramspider --list "$sorted_subdomains_file" 
cat results/*.txt > "$paramspider_urls" 
rm -rf results/

# Add new spidered urls to full list
cat "$paramspider_urls" | tee -a "$target_links_file"
echo "Paramspider links obtained..."

echo ''
echo "Extracting URLs with katana..."
katana -u "$valid_subdomains_file" -d 4 -ef png,jpg,gif,jpeg,swf,woff,svg,pdf,tiff,tif,bmp,webp,ico,mp4,mov,js,css,eps,raw -kf -nc -ct 1800 -silent -c 5 -p 2 -rl 50 -o "$katana_urls"

# Add new spidered urls to full list
cat "$katana_urls" | tee -a "$target_links_file"
echo "URLs extracted using katana..."

echo ''
echo "Sorting links..."
sort -u "$target_links_file" -o "$sorted_links_file"
echo "Links sorted."

echo ''
echo "Extracting Filetype links..."
cat "$sorted_links_file" | grep -e .js -e .php -e .xml -e .log -e .sql -e .gz -e .zip -e .java -e .py -e .bak -e .tmp -e .aspx | tee -a "$file_type"
echo "Filetype links extracted."

echo ''
echo "Extracting links with '=' parameter..."
cat "$sorted_links_file" | grep '=' | tee -a "$endpoint_parameter_file"
# Check if the = endpoints file is empty and remove it if necessary
if [ ! -s "$endpoint_parameter_file" ]; then
    echo "Removing empty = endpoints file."
    rm "$endpoint_parameter_file"
fi

echo "Links with '=' parameter extracted."
    
echo ''
echo "Running kxss..."
cat "$endpoint_parameter_file" | kxss | sudo tee -a "$parameter_kxss_file"
# Check if the kxss file is empty and remove it if necessary
if [ ! -s "$parameter_kxss_file" ]; then
    echo "Removing empty = endpoints file."
    rm "$parameter_kxss_file"
fi

echo "kxss processes completed."

echo ''
echo "Launching nuclie..."
nuclei -l "$file_type" -t /root/nuclei-templates/http/exposures -o "$type_bugs_file"
# Check if the Filetype_bugs file is empty and remove it if necessary
if [ ! -s "$type_bugs_file" ]; then
    rm "$type_bugs_file"
fi
echo "Exposures scanning is completed."

nuclei -l "$sorted_subdomains_file" -t /root/nuclei-templates/http/cves -o "$cves_bugs"
# Check if the cves_vulnerabilites file is empty and remove it if necessary
if [ ! -s "$cves_bugs" ]; then
    rm "$cves_bugs"
fi
echo "CVEs vulnerabilities scanning is completed."

# Save finish execution time
end=`date +%s`
echo ''
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo ''
echo Execution time was `expr $end - $start` seconds

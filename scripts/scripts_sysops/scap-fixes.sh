#!/bin/bash

# Disable prelinking altogether
#
# if grep -q ^PRELINKING /etc/sysconfig/prelink
# then
#   sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
# else
#   echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
#   echo "PRELINKING=no" >> /etc/sysconfig/prelink
# fi

/usr/sbin/aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf

cat << LOGINDEFS >> /etc/login.defs
PASS_MIN_LEN 14
PASS_MIN_DAYS 1
PASS_MAX_DAYS 60
LOGINDEFS

sed -i '/pam_limits.so/a session      required     pam_lastlog.so showfailed' /etc/pam.d/system-auth

# Use Only FIPS Approved MACs
grep -qi ^MACs /etc/ssh/sshd_config && \
  sed -i "s/MACs.*/MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1" >> /etc/ssh/sshd_config
fi

# Enable Use of Privilege Seperation
grep -qi ^UsePrivilegeSeparation /etc/ssh/sshd_config && \
  sed -i "s/UsePrivilegeSeparation.*/UsePrivilegeSeparation yes/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1" >> /etc/ssh/sshd_config
fi

# Disable GSSAPI Authentication
grep -qi ^GSSAPIAuthentication /etc/ssh/sshd_config && \
  sed -i "s/GSSAPIAuthentication.*/GSSAPIAuthentication no/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
fi

# Disable Kerberos Authentication
grep -qi ^#KerberosAuthentication /etc/ssh/sshd_config && \
  sed -i "s/#KerberosAuthentication.*/KerberosAuthentication no/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
fi

# Enable Use of StrictModes
grep -qi ^#StrictModes /etc/ssh/sshd_config && \
  sed -i "s/#StrictModes.*/StrictModes yes/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "StrictModes yes" >> /etc/ssh/sshd_config
fi

# Disable Compression Or Set Compression to delayed
grep -qi ^#Compression /etc/ssh/sshd_config && \
  sed -i "s/#Compression.*/Compression delayed/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "Compression delayed" >> /etc/ssh/sshd_config
fi

# Disable Compression Or Set Compression to delayed
grep -qi ^Ciphers /etc/ssh/sshd_config && \
  sed -i "s/Ciphers.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc/gI" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config
fi
# Disable kdump.service for all systemd targets
systemctl disable kdump.service

# Configure Kernel Parameter for Accepting Source-Routed Packets for All Interfaces
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/50-sysctl.conf

# Enable Randomized Layout of Virtual Address Space
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/50-sysctl.conf

# Prevent Log In to Accounts With Empty Password
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth

# Set Password Retry Prompts Permitted Per-Session
var_password_pam_retry="3"

if grep -q "retry=" /etc/pam.d/system-auth; then
	sed -i --follow-symlinks "s/\(retry *= *\).*/\1$var_password_pam_retry/" /etc/pam.d/system-auth
else
	sed -i --follow-symlinks "/pam_pwquality.so/ s/$/ retry=$var_password_pam_retry/" /etc/pam.d/system-auth
fi

echo $'\nmaxclassrepeat 2' >> /etc/security/pwquality.conf

# Set Deny For Failed Password Attempts
var_accounts_passwords_pam_faillock_deny="3"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do

	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, deny directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*deny=" $pamFile; then

			# both pam_faillock.so & deny present, just correct deny directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile

		# pam_faillock.so present, but deny directive not yet
		else

			# append correct deny value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'deny' option
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

# Set Lockout Time For Failed Password Attempts
var_accounts_passwords_pam_faillock_unlock_time="604800"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do

	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, unlock_time directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*unlock_time=" $pamFile; then

			# both pam_faillock.so & unlock_time present, just correct unlock_time directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile

		# pam_faillock.so present, but unlock_time directive not yet
		else

			# append correct unlock_time value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'unlock_time' option
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

# Set Interval For Counting Failed Password Attempts
var_accounts_passwords_pam_faillock_fail_interval="900"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do

	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, 'fail_interval' directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*fail_interval=" $pamFile; then

			# both pam_faillock.so & 'fail_interval' present, just correct 'fail_interval' directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(fail_interval *= *\).*/\1\2$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(fail_interval *= *\).*/\1\2$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile

		# pam_faillock.so present, but 'fail_interval' directive not yet
		else

			# append correct 'fail_interval' value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ fail_interval=$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ fail_interval=$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'fail_interval' option
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" $pamFile
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" $pamFile
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

# Limit Password Reuse
var_password_pam_unix_remember="5"

if grep -q "remember=" /etc/pam.d/system-auth; then
	sed -i --follow-symlinks "s/\(^password.*sufficient.*pam_unix.so.*\)\(\(remember *= *\)[^ $]*\)/\1remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
else
	sed -i --follow-symlinks "/^password[[:space:]]\+sufficient[[:space:]]\+pam_unix.so/ s/$/ remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
fi

## Ensure auditd Collects Information on the Use of Privileged Commands
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function perform_audit_rules_privileged_commands_remediation {
#
# Load function arguments into local variables
local tool="$1"
local min_auid="$2"

# Check sanity of the input
if [ $# -ne "2" ]
then
        echo "Usage: perform_audit_rules_privileged_commands_remediation 'auditctl | augenrules' '500 | 1000'"
        echo "Aborting."
        exit 1
fi

declare -a files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then:
# * add '/etc/audit/audit.rules'to the list of files to be inspected,
# * specify '/etc/audit/audit.rules' as the output audit file, where
#   missing rules should be inserted
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("/etc/audit/audit.rules")
        output_audit_file="/etc/audit/audit.rules"
#
# If the audit tool is 'augenrules', then:
# * add '/etc/audit/rules.d/*.rules' to the list of files to be inspected
#   (split by newline),
# * specify /etc/audit/rules.d/privileged.rules' as the output file, where
#   missing rules should be inserted
elif [ "$tool" == 'augenrules' ]
then
        IFS=$'\n' files_to_inspect=($(find /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -print))
        output_audit_file="/etc/audit/rules.d/privileged.rules"
fi

# Obtain the list of SUID/SGID binaries on the particular system (split by newline)
# into privileged_binaries array
IFS=$'\n' privileged_binaries=($(find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null))

# Keep list of SUID/SGID binaries that have been already handled within some previous iteration
declare -a sbinaries_to_skip=()

# For each found sbinary in privileged_binaries list
for sbinary in "${privileged_binaries[@]}"
do

        # Replace possible slash '/' character in sbinary definition so we could use it in sed expressions below
        sbinary_esc=${sbinary//$'/'/$'\/'}
        # Check if this sbinary wasn't already handled in some of the previous iterations
        # Return match only if whole sbinary definition matched (not in the case just prefix matched!!!)
        if [[ $(sed -ne "/${sbinary_esc}$/p" <<< ${sbinaries_to_skip[@]}) ]]
        then
                # If so, don't process it second time & go to process next sbinary
                continue
        fi

        # Reset the counter of inspected files when starting to check
        # presence of existing audit rule for new sbinary
        local count_of_inspected_files=0

        # For each audit rules file from the list of files to be inspected
        for afile in "${files_to_inspect[@]}"
        do

                # Search current audit rules file's content for match. Match criteria:
                # * existing rule is for the same SUID/SGID binary we are currently processing (but
                #   can contain multiple -F path= elements covering multiple SUID/SGID binaries)
                # * existing rule contains all arguments from expected rule form (though can contain
                #   them in arbitrary order)

                base_search=$(sed -e "/-a always,exit/!d" -e "/-F path=${sbinary_esc}$/!d"   \
                                  -e "/-F path=[^[:space:]]\+/!d" -e "/-F perm=.*/!d"       \
                                  -e "/-F auid>=${min_auid}/!d" -e "/-F auid!=4294967295/!d"  \
                                  -e "/-k privileged/!d" $afile)

                # Increase the count of inspected files for this sbinary
                count_of_inspected_files=$((count_of_inspected_files + 1))

                # Define expected rule form for this binary
                expected_rule="-a always,exit -F path=${sbinary} -F perm=x -F auid>=${min_auid} -F auid!=4294967295 -k privileged"

                # Require execute access type to be set for existing audit rule
                exec_access='x'

                # Search current audit rules file's content for presence of rule pattern for this sbinary
                if [[ $base_search ]]
                then

                        # Current audit rules file already contains rule for this binary =>
                        # Store the exact form of found rule for this binary for further processing
                        concrete_rule=$base_search

                        # Select all other SUID/SGID binaries possibly also present in the found rule
                        IFS=$'\n' handled_sbinaries=($(grep -o -e "-F path=[^[:space:]]\+" <<< $concrete_rule))
                        IFS=$' ' handled_sbinaries=(${handled_sbinaries[@]//-F path=/})

                        # Merge the list of such SUID/SGID binaries found in this iteration with global list ignoring duplicates
                        sbinaries_to_skip=($(for i in "${sbinaries_to_skip[@]}" "${handled_sbinaries[@]}"; do echo $i; done | sort -du))

                        # Separate concrete_rule into three sections using hash '#'
                        # sign as a delimiter around rule's permission section borders
                        concrete_rule=$(echo $concrete_rule | sed -n "s/\(.*\)\+\(-F perm=[rwax]\+\)\+/\1#\2#/p")

                        # Split concrete_rule into head, perm, and tail sections using hash '#' delimiter
                        IFS=$'#' read rule_head rule_perm rule_tail <<<  "$concrete_rule"

                        # Extract already present exact access type [r|w|x|a] from rule's permission section
                        access_type=${rule_perm//-F perm=/}

                        # Verify current permission access type(s) for rule contain 'x' (execute) permission
                        if ! grep -q "$exec_access" <<< "$access_type"
                        then

                                # If not, append the 'x' (execute) permission to the existing access type bits
                                access_type="$access_type$exec_access"
                                # Reconstruct the permissions section for the rule
                                new_rule_perm="-F perm=$access_type"
                                # Update existing rule in current audit rules file with the new permission section
                                sed -i "s#${rule_head}\(.*\)${rule_tail}#${rule_head}${new_rule_perm}${rule_tail}#" $afile

                        fi

                # If the required audit rule for particular sbinary wasn't found yet, insert it under following conditions:
                #
                # * in the "auditctl" mode of operation insert particular rule each time
                #   (because in this mode there's only one file -- /etc/audit/audit.rules to be inspected for presence of this rule),
                #
                # * in the "augenrules" mode of operation insert particular rule only once and only in case we have already
                #   searched all of the files from /etc/audit/rules.d/*.rules location (since that audit rule can be defined
                #   in any of those files and if not, we want it to be inserted only once into /etc/audit/rules.d/privileged.rules file)
                #
                elif [ "$tool" == "auditctl" ] || [[ "$tool" == "augenrules" && $count_of_inspected_files -eq "${#files_to_inspect[@]}" ]]
                then

                        # Current audit rules file's content doesn't contain expected rule for this
                        # SUID/SGID binary yet => append it
                        echo $expected_rule >> $output_audit_file
                fi

        done

done

}

perform_audit_rules_privileged_commands_remediation "auditctl" "1000"
perform_audit_rules_privileged_commands_remediation "augenrules" "1000"

# Set Password Strength Minimum Different Categories
var_password_pam_minclass="4"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal CCENUM.
  # If CCENUM exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != 'CCENUM' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=${key//[!a-zA-Z]/}

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" $stripped_key $value
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    echo -ne "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -ne "\n$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/security/pwquality.conf' '^minclass' $var_password_pam_minclass 'CCE-27115-5' '%s = %s'

echo "TMOUT=600" >> /etc/profile.d/tmout.sh
echo "export TMOUT" >> /etc/profile.d/tmout.sh

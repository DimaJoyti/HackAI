#!/bin/bash

# Script to fix TestResult structures in vulnerability_scanner.go

FILE="pkg/testing/vulnerability_scanner.go"

# Create a temporary file for processing
TEMP_FILE=$(mktemp)

# Read the file and process it
awk '
BEGIN { in_testresult = 0; brace_count = 0 }

# Detect start of TestResult structure
/result := &TestResult\{/ {
    in_testresult = 1
    brace_count = 1
    
    # Extract the ID for naming
    getline next_line
    if (match(next_line, /ID:.*"([^"]+)"/, arr)) {
        test_id = arr[1]
    } else {
        test_id = "test_" systime()
    }
    
    # Print the new structure
    print "\t// Create security test result"
    print "\tsecurityResult := &SecurityTestResult{"
    print "\t\tVulnerabilitiesFound: len(vulnerabilities),"
    print "\t\tSecurityScore:        vs.calculateSecurityScore(vulnerabilities),"
    print "\t\tVulnerabilities:      vulnerabilities,"
    print "\t}"
    print ""
    print "\tresult := &TestResult{"
    print "\t\tTestID:    fmt.Sprintf(\"" test_id "\", startTime.UnixNano()),"
    print "\t\tName:      testName,"
    print "\t\tStatus:    TestStatusPassed,"
    print "\t\tStartTime: startTime,"
    print "\t\tEndTime:   endTime,"
    print "\t\tDuration:  duration,"
    print "\t\tSecurity:  securityResult,"
    
    next
}

# Count braces while inside TestResult
in_testresult == 1 {
    # Count opening and closing braces
    for (i = 1; i <= length($0); i++) {
        char = substr($0, i, 1)
        if (char == "{") brace_count++
        if (char == "}") brace_count--
    }
    
    # Handle Metadata field specially
    if (/Metadata:/) {
        print $0
        next
    }
    
    # Handle Recommendations -> Logs conversion
    if (/Recommendations:/) {
        gsub(/Recommendations:/, "Logs:")
        print $0
        next
    }
    
    # Skip old fields
    if (/ID:/ || /TestType:/ || /TestName:/ || /Passed:/ || /Score:/ || /Severity:/ || /Vulnerabilities:/ || /TestMetrics:/) {
        next
    }
    
    # If we reach the end of the structure
    if (brace_count == 0) {
        in_testresult = 0
        print $0
        next
    }
    
    # Print other lines as-is
    print $0
    next
}

# Print all other lines as-is
{ print $0 }
' "$FILE" > "$TEMP_FILE"

# Replace the original file
mv "$TEMP_FILE" "$FILE"

echo "Fixed TestResult structures in $FILE"

# ============================================================================
# DISCLAIMER: 
# This script is provided "AS IS" without warranty of any kind, either express or implied,
# including but not limited to the implied warranties of merchantability and/or fitness for a
# particular purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or anyone else
# involved in the creation, production, or delivery of the script be liable for any damages
# whatsoever (including, without limitation, damages for loss of business profits, business
# interruption, loss of business information, or other pecuniary loss) arising out of the use of
# or inability to use the sample scripts or documentation, even if Microsoft has been advised of
# the possibility of such damages.
# ============================================================================

set -e

# ============================================================================
# PARAMETERS
# ============================================================================

ORGANIZATION=""
OUTPUT_PATH="./ghas-reports"
DETAILED_AUDIT=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--organization)
            ORGANIZATION="$2"
            shift 2
            ;;
        -p|--output-path)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -d|--detailed-audit)
            DETAILED_AUDIT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 -o|--organization <org> [-p|--output-path <path>] [-d|--detailed-audit]"
            echo ""
            echo "Options:"
            echo "  -o, --organization    GitHub organization name (required)"
            echo "  -p, --output-path     Output directory path (default: ./ghas-reports)"
            echo "  -d, --detailed-audit  Enable detailed audit mode (includes repository details, features, and commit details)"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Prompt for Organization if not provided
if [[ -z "$ORGANIZATION" ]]; then
    echo ""
    echo -e "${YELLOW}GitHub Organization not specified.${NC}"
    echo -e "${CYAN}Please enter the name of the GitHub Organization to audit:${NC}"
    read -p "Organization: " ORGANIZATION
    
    if [[ -z "$ORGANIZATION" ]]; then
        echo -e "${RED}Error: Organization name is required.${NC}"
        exit 1
    fi
fi

# Prompt for DetailedAudit mode if not specified via flag
if [[ "$DETAILED_AUDIT" == "false" ]] && [[ ! -t 0 ]]; then
    # Non-interactive mode, use default
    :
elif [[ "$DETAILED_AUDIT" == "false" ]]; then
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                            AUDIT MODE SELECTION                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}  [1] BASIC MODE${NC}"
    echo -e "${GRAY}      • GHAS licensing details (who enabled GHAS, when, and how)${NC}"
    echo -e "${GRAY}      • Active committers count per repository${NC}"
    echo -e "${GRAY}      • Summary reports (JSON + CSV)${NC}"
    echo -e "${GRAY}      • Faster execution, minimal API calls${NC}"
    echo ""
    echo -e "${YELLOW}  [2] DETAILED MODE${NC}"
    echo -e "${GRAY}      • Everything in BASIC mode, plus:${NC}"
    echo -e "${GRAY}      • Repository metadata (creation date, size, language, branch)${NC}"
    echo -e "${GRAY}      • GHAS features status (Secret Scanning, Dependabot, Code Scanning)${NC}"
    echo -e "${GRAY}      • Detailed commit history for each active committer${NC}"
    echo -e "${GRAY}      • Longer execution time, more API calls required${NC}"
    echo ""
    
    read -p "Select audit mode (1 or 2) [default: 1]: " choice
    
    if [[ -z "$choice" ]]; then
        choice="1"
    fi
    
    if [[ "$choice" == "2" ]]; then
        DETAILED_AUDIT=true
    elif [[ "$choice" != "1" ]]; then
        echo -e "${YELLOW}Invalid choice. Using BASIC mode.${NC}"
        DETAILED_AUDIT=false
    fi
fi

# ============================================================================
# COLORS (need to be defined before functions)
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
DARKGRAY='\033[1;30m'
NC='\033[0m' # No Color

# ============================================================================
# AUTHENTICATION AND PERMISSIONS CHECK
# ============================================================================

test_github_cli() {
    echo ""
    echo -e "${CYAN}Checking GitHub CLI installation...${NC}"
    
    if command -v gh >/dev/null 2>&1; then
        local gh_version=$(gh --version 2>&1 | head -n 1)
        echo -e "${GREEN}  ✓ GitHub CLI found: $gh_version${NC}"
        return 0
    else
        echo -e "${RED}  ✗ GitHub CLI not found${NC}"
        echo ""
        echo -e "${YELLOW}Please install GitHub CLI:${NC}"
        echo -e "${GRAY}  macOS: brew install gh${NC}"
        echo -e "${GRAY}  Linux: See https://github.com/cli/cli/blob/trunk/docs/install_linux.md${NC}"
        echo -e "${GRAY}  Or visit: https://cli.github.com/${NC}"
        return 1
    fi
}

test_github_authentication() {
    echo -e "${CYAN}Checking GitHub authentication...${NC}"
    
    if gh auth status >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Authenticated with GitHub${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Not authenticated with GitHub${NC}"
        echo ""
        echo -e "${YELLOW}Please authenticate with GitHub CLI:${NC}"
        echo -e "${GRAY}  gh auth login${NC}"
        return 1
    fi
}

test_organization_access() {
    local org_name="$1"
    
    echo -e "${CYAN}Verifying access to organization '$org_name'...${NC}"
    
    if gh api "/orgs/$org_name" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Organization found and accessible${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Cannot access organization '$org_name'${NC}"
        echo ""
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "${GRAY}  • Organization name is incorrect${NC}"
        echo -e "${GRAY}  • You don't have access to this organization${NC}"
        echo -e "${GRAY}  • Organization doesn't exist${NC}"
        return 1
    fi
}

test_billing_permissions() {
    local org_name="$1"
    
    echo -e "${CYAN}Checking billing permissions...${NC}"
    
    if gh api "/orgs/$org_name/settings/billing/advanced-security?advanced_security_product=code_security" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Billing access confirmed${NC}"
        return 0
    else
        echo -e "${YELLOW}  ⚠ No billing access for organization '$org_name'${NC}"
        echo -e "${GRAY}  → Script will continue, but some billing data may be incomplete${NC}"
        return 0  # Non-blocking warning
    fi
}

test_prerequisites() {
    local org_name="$1"
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                       PREREQUISITES VERIFICATION                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local all_passed=true
    
    if ! test_github_cli; then
        all_passed=false
    fi
    
    if ! test_github_authentication; then
        all_passed=false
    fi
    
    if ! test_organization_access "$org_name"; then
        all_passed=false
    fi
    
    if ! test_billing_permissions "$org_name"; then
        : # Non-blocking, already returns 0
    fi
    
    echo ""
    
    if [[ "$all_passed" == "true" ]]; then
        echo -e "${GREEN}✓ All prerequisites met. Starting audit...${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ Prerequisites check failed. Please resolve the issues above.${NC}"
        echo ""
        return 1
    fi
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Global rate limit tracking
declare -A RATE_LIMIT_INFO=(
    [Limit]=0
    [Remaining]=0
    [Used]=0
    [Reset]=0
    [Resource]=""
    [LastCheck]=0
)

update_rate_limit_info() {
    local response_headers="$1"
    
    if [[ -z "$response_headers" ]]; then
        return
    fi
    
    while IFS=': ' read -r key value; do
        case "$key" in
            x-ratelimit-limit)
                RATE_LIMIT_INFO[Limit]=$value
                ;;
            x-ratelimit-remaining)
                RATE_LIMIT_INFO[Remaining]=$value
                ;;
            x-ratelimit-used)
                RATE_LIMIT_INFO[Used]=$value
                ;;
            x-ratelimit-reset)
                RATE_LIMIT_INFO[Reset]=$value
                ;;
            x-ratelimit-resource)
                RATE_LIMIT_INFO[Resource]=$value
                ;;
        esac
    done <<< "$response_headers"
    
    RATE_LIMIT_INFO[LastCheck]=$(date +%s)
    
    # Warn if approaching rate limit
    if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 100 ]] && [[ ${RATE_LIMIT_INFO[Remaining]} -gt 0 ]]; then
        local reset_time=$(date -d "@${RATE_LIMIT_INFO[Reset]}" '+%H:%M:%S' 2>/dev/null || \
                          date -r "${RATE_LIMIT_INFO[Reset]}" '+%H:%M:%S' 2>/dev/null)
        echo -e "${YELLOW}  Rate limit low: ${RATE_LIMIT_INFO[Remaining]} requests remaining (resets at $reset_time)${NC}" >&2
    fi
}

get_rate_limit_status() {
    local response=$(gh api rate_limit --include 2>&1)
    
    if [[ $? -eq 0 ]]; then
        # Extract headers (everything before the first {)
        local headers=$(echo "$response" | sed '/^{/,$d')
        # Extract body (everything from the first {)
        local body=$(echo "$response" | sed -n '/^{/,$p')
        
        update_rate_limit_info "$headers"
        
        # Update with more detailed info from API
        if [[ -n "$body" ]]; then
            RATE_LIMIT_INFO[Limit]=$(echo "$body" | jq -r '.resources.core.limit // 0')
            RATE_LIMIT_INFO[Remaining]=$(echo "$body" | jq -r '.resources.core.remaining // 0')
            RATE_LIMIT_INFO[Used]=$(echo "$body" | jq -r '.resources.core.used // 0')
            RATE_LIMIT_INFO[Reset]=$(echo "$body" | jq -r '.resources.core.reset // 0')
        fi
    fi
}

wait_for_rate_limit() {
    local minimum_remaining=${1:-10}
    local force=${2:-false}
    
    get_rate_limit_status
    
    if [[ "$force" == "true" ]] || [[ ${RATE_LIMIT_INFO[Remaining]} -lt $minimum_remaining ]]; then
        if [[ ${RATE_LIMIT_INFO[Reset]} -gt 0 ]]; then
            local now=$(date +%s)
            local wait_seconds=$((RATE_LIMIT_INFO[Reset] - now))
            
            if [[ $wait_seconds -gt 0 ]]; then
                local reset_time=$(date -d "@${RATE_LIMIT_INFO[Reset]}" '+%H:%M:%S' 2>/dev/null || \
                                  date -r "${RATE_LIMIT_INFO[Reset]}" '+%H:%M:%S' 2>/dev/null)
                echo -e "${YELLOW}Rate limit exceeded. Waiting until $reset_time ($wait_seconds seconds)...${NC}" >&2
                sleep $((wait_seconds + 1))
                
                # Verify rate limit has reset
                get_rate_limit_status
                echo -e "${GREEN}  ✓ Rate limit reset. Continuing...${NC}" >&2
            fi
        fi
    fi
}

invoke_github_api() {
    local endpoint="$1"
    local paginate="${2:-false}"
    local throttle_ms="${3:-0}"
    
    # Check rate limit before making request
    if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 10 ]] && [[ ${RATE_LIMIT_INFO[Remaining]} -gt 0 ]]; then
        wait_for_rate_limit 10
    fi
    
    # Add throttling if specified
    if [[ $throttle_ms -gt 0 ]]; then
        sleep $(echo "scale=3; $throttle_ms / 1000" | bc)
    fi
    
    # Execute request with timeout protection
    if [[ "$paginate" == "true" ]]; then
        # For paginated requests, get data without headers first
        local response=$(timeout 300 gh api --paginate "$endpoint" 2>&1)
        local exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            echo -e "${RED}  Error: API request timed out after 5 minutes${NC}" >&2
            return 1
        fi
        
        if [[ $exit_code -eq 0 ]] && [[ -n "$response" ]]; then
            # Update rate limit info with a separate call
            local header_response=$(timeout 30 gh api --include "$endpoint" 2>&1)
            if [[ $? -eq 0 ]] && [[ -n "$header_response" ]]; then
                local headers=$(echo "$header_response" | sed '/^{/,$d')
                update_rate_limit_info "$headers"
            fi
            echo "$response"
            return 0
        fi
    else
        # For single requests, get headers and body
        local response=$(timeout 60 gh api --include "$endpoint" 2>&1)
        local exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            echo -e "${RED}  Error: API request timed out${NC}" >&2
            return 1
        fi
        
        if [[ $exit_code -eq 0 ]] && [[ -n "$response" ]]; then
            # Extract headers (everything before the first { or [)
            local headers=$(echo "$response" | sed '/^[{\[]/,$d')
            # Extract body (everything from the first { or [)
            local body=$(echo "$response" | sed -n '/^[{\[]/,$p')
            
            update_rate_limit_info "$headers"
            echo "$body"
            return 0
        else
            echo -e "${YELLOW}  Warning: API request failed for $endpoint${NC}" >&2
        fi
    fi
    
    return 1
}

get_normalized_repo_name() {
    local name="$1"
    if [[ "$name" == *"/"* ]]; then
        echo "${name##*/}"
    else
        echo "$name"
    fi
}

convert_to_formatted_timestamp() {
    local timestamp="$1"
    
    if [[ -z "$timestamp" ]] || [[ "$timestamp" == "0" ]]; then
        echo ""
        return
    fi
    
    # Check if it's a Unix timestamp (milliseconds or seconds)
    if [[ "$timestamp" =~ ^[0-9]+$ ]]; then
        if [[ ${#timestamp} -gt 10 ]]; then
            # Milliseconds
            date -d "@$((timestamp / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            date -r "$((timestamp / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            echo "$timestamp"
        else
            # Seconds
            date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            date -r "$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            echo "$timestamp"
        fi
    else
        echo "$timestamp"
    fi
}

convert_to_iso8601() {
    local date_string="$1"
    
    if [[ -z "$date_string" ]]; then
        echo ""
        return
    fi
    
    date -d "$date_string" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
    date -j -f "%Y-%m-%dT%H:%M:%SZ" "$date_string" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
    echo "$date_string"
}

get_first_enable_event() {
    local events_json="$1"
    
    if [[ -z "$events_json" ]] || [[ "$events_json" == "[]" ]]; then
        echo "null"
        return
    fi
    
    # Priority patterns for finding the first enable event (note: using capitalized field names)
    local priority_patterns=(
        '.Action == "repository_security_configuration.applied" and .Actor != "" and .Actor != null'
        '(.Action | test("code_security.*enable|advanced_security.*enabled")) and .Actor != "" and .Actor != null'
        '(.Action | test("secret_scanning.*enable")) and .Actor != "" and .Actor != null'
        '(.Action | test("code_scanning.*enable")) and .Actor != "" and .Actor != null'
        '(.Action | test("enable")) and .Actor != "" and .Actor != null'
        '.Action == "repo.create" and .Actor != "" and .Actor != null'
    )
    
    for pattern in "${priority_patterns[@]}"; do
        local result=$(echo "$events_json" | jq -r "sort_by(.Timestamp) | map(select($pattern)) | first // null")
        if [[ "$result" != "null" ]]; then
            echo "$result"
            return
        fi
    done
    
    echo "null"
}

# ============================================================================
# CORE API FUNCTIONS
# ============================================================================

get_ghas_billing_info() {
    local organization="$1"
    
    local code_security_committers=0
    local code_security_repos=0
    local secret_protection_committers=0
    local secret_protection_repos=0
    local max_committers=0
    local purchased_committers=0
    local repositories="[]"
    
    local products=("code_security" "secret_protection")
    
    for product in "${products[@]}"; do
        echo -e "${GRAY}  → Fetching billing data for $product...${NC}" >&2
        local response=$(invoke_github_api "/orgs/$organization/settings/billing/advanced-security?advanced_security_product=$product" false 0)
        
        if [[ -n "$response" ]] && [[ "$response" != "{}" ]]; then
            local prod_committers=$(echo "$response" | jq -r '.total_advanced_security_committers // 0')
            local prod_count=$(echo "$response" | jq -r '.total_count // 0')
            local prod_max=$(echo "$response" | jq -r '.maximum_advanced_security_committers // 0')
            local prod_purchased=$(echo "$response" | jq -r '.purchased_advanced_security_committers // 0')
            local prod_repos=$(echo "$response" | jq -c '.repositories // []')
            
            # Store product-specific metrics
            if [[ "$product" == "code_security" ]]; then
                code_security_committers=$prod_committers
                code_security_repos=$prod_count
                echo -e "${GRAY}     ✓ Code Security: $prod_committers committers in $prod_count repos${NC}" >&2
            elif [[ "$product" == "secret_protection" ]]; then
                secret_protection_committers=$prod_committers
                secret_protection_repos=$prod_count
                echo -e "${GRAY}     ✓ Secret Protection: $prod_committers committers in $prod_count repos${NC}" >&2
            fi
            
            if [[ $prod_max -gt $max_committers ]]; then
                max_committers=$prod_max
            fi
            
            if [[ $prod_purchased -gt $purchased_committers ]]; then
                purchased_committers=$prod_purchased
            fi
            
            # Merge repositories with product marker
            local tagged_repos=$(echo "$prod_repos" | jq --arg pt "$product" '[.[] | . + {product_type: $pt}]')
            
            # Add or merge repositories
            repositories=$(echo "$repositories $tagged_repos" | jq -s '
                .[0] as $existing | .[1] as $new |
                ($existing + ($new | map(
                    . as $item |
                    ($existing | map(select(.name == $item.name)) | length) as $exists |
                    if $exists > 0 then
                        . + {product_type_additional: .product_type}
                    else
                        .
                    end
                ))) | unique_by(.name)
            ')
        fi
    done
    
    # Calculate unique repository count
    local unique_count=$(echo "$repositories" | jq 'length')
    
    jq -n \
        --arg total "$unique_count" \
        --arg max "$max_committers" \
        --arg purchased "$purchased_committers" \
        --arg code_comm "$code_security_committers" \
        --arg code_repos "$code_security_repos" \
        --arg secret_comm "$secret_protection_committers" \
        --arg secret_repos "$secret_protection_repos" \
        --argjson repositories "$repositories" \
        '{
            total_count: ($total | tonumber),
            maximum_advanced_security_committers: ($max | tonumber),
            purchased_advanced_security_committers: ($purchased | tonumber),
            code_security_committers: ($code_comm | tonumber),
            code_security_repositories: ($code_repos | tonumber),
            secret_protection_committers: ($secret_comm | tonumber),
            secret_protection_repositories: ($secret_repos | tonumber),
            repositories: $repositories
        }'
}

get_repository_details() {
    local organization="$1"
    shift
    local repo_names=("$@")
    
    local details="{}"
    local counter=0
    local total=${#repo_names[@]}
    
    echo -e "${GRAY}  → Fetching details for $total repositories...${NC}" >&2
    
    for repo_name in "${repo_names[@]}"; do
        counter=$((counter + 1))
        
        if [[ $((counter % 20)) -eq 0 ]]; then
            echo -e "${DARKGRAY}     Progress: $counter/$total${NC}" >&2
            get_rate_limit_status
            if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 30 ]]; then
                wait_for_rate_limit 30
            fi
        fi
        
        local repo_json=$(invoke_github_api "/repos/$organization/$repo_name" false 50)
        if [[ -n "$repo_json" ]]; then
            local repo_detail=$(echo "$repo_json" | jq -c '{
                Repository: .name,
                IsPrivate: .private,
                CreatedAt: .created_at,
                UpdatedAt: .updated_at,
                PushedAt: .pushed_at,
                Size: .size,
                Language: .language,
                DefaultBranch: .default_branch
            }')
            
            details=$(echo "$details" | jq --arg key "$repo_name" --argjson val "$repo_detail" '. + {($key): $val}')
        fi
    done
    
    echo "$details"
}

get_repository_features() {
    local organization="$1"
    shift
    local repo_names=("$@")
    
    local features="{}"
    local counter=0
    local total=${#repo_names[@]}
    
    echo -e "${GRAY}  → Fetching GHAS features for $total repositories...${NC}" >&2
    
    for repo_name in "${repo_names[@]}"; do
        counter=$((counter + 1))
        
        echo -en "${GRAY}  → [$counter/$total] Checking $repo_name...${NC}" >&2
        
        if [[ $((counter % 20)) -eq 0 ]]; then
            echo "" >&2
            get_rate_limit_status
            if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 30 ]]; then
                wait_for_rate_limit 30
            fi
        fi
        
        local repo_json=$(invoke_github_api "/repos/$organization/$repo_name" false 50)
        if [[ -z "$repo_json" ]]; then
            echo -e " ${RED}✗${NC}" >&2
            continue
        fi
        
        local sec=$(echo "$repo_json" | jq -c '.security_and_analysis // {}')
        
        # Check Code Scanning Default Setup
        local code_scanning_state="not-configured"
        local code_scanning_langs=""
        local code_scanning_schedule=""
        
        local cs_setup=$(invoke_github_api "/repos/$organization/$repo_name/code-scanning/default-setup" false 50 2>/dev/null)
        if [[ -n "$cs_setup" ]]; then
            code_scanning_state=$(echo "$cs_setup" | jq -r '.state // "not-configured"')
            if [[ "$code_scanning_state" == "configured" ]]; then
                code_scanning_langs=$(echo "$cs_setup" | jq -r '.languages // [] | join(", ")')
                code_scanning_schedule=$(echo "$cs_setup" | jq -r '.schedule // ""')
            fi
        fi
        
        # Check Dependabot Alerts
        local dependabot_alerts="disabled"
        if invoke_github_api "/repos/$organization/$repo_name/vulnerability-alerts" false 50 >/dev/null 2>&1; then
            dependabot_alerts="enabled"
        fi
        
        local feature_obj=$(echo "$sec" | jq -c \
            --arg repo "$repo_name" \
            --arg cs_state "$code_scanning_state" \
            --arg cs_langs "$code_scanning_langs" \
            --arg cs_schedule "$code_scanning_schedule" \
            --arg dep_alerts "$dependabot_alerts" \
            '{
                Repository: $repo,
                SecretScanning: .secret_scanning.status,
                SecretScanningPushProtection: .secret_scanning_push_protection.status,
                DependabotAlerts: $dep_alerts,
                DependabotSecurityUpdates: (.dependabot_security_updates.status // "disabled"),
                CodeScanningDefaultSetup: $cs_state,
                CodeScanningLanguages: $cs_langs,
                CodeScanningSchedule: $cs_schedule
            }')
        
        features=$(echo "$features" | jq --arg key "$repo_name" --argjson val "$feature_obj" '. + {($key): $val}')
        
        echo -e " ${GREEN}✓${NC}" >&2
    done
    
    echo "$features"
}

get_ghas_features_status() {
    local organization="$1"
    
    # Use paginate to get all repositories
    local repos=$(invoke_github_api "/orgs/$organization/repos?per_page=100&type=all" true 0)
    
    if [[ -z "$repos" ]] || [[ "$repos" == "[]" ]]; then
        jq -n \
            --arg org "$organization" \
            '{
                organization: $org,
                total_repositories: 0,
                ghas_enabled_repositories: 0,
                repositories: []
            }'
        return
    fi
    
    local total_repos=$(echo "$repos" | jq 'length')
    local ghas_enabled_repos="[]"
    
    echo -e "${GRAY}  → Processing $total_repos total repositories...${NC}" >&2
    
    local repo_counter=0
    while IFS= read -r repo_name; do
        [[ -z "$repo_name" ]] && continue
        
        repo_counter=$((repo_counter + 1))
        
        # Throttle requests to avoid rate limiting (check every 50 repos)
        if [[ $((repo_counter % 50)) -eq 0 ]]; then
            get_rate_limit_status
            echo -e "${GRAY}  → Progress: $repo_counter/$total_repos repos | Rate limit: ${RATE_LIMIT_INFO[Remaining]}/${RATE_LIMIT_INFO[Limit]}${NC}" >&2
            
            if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 50 ]]; then
                wait_for_rate_limit 50
            fi
        fi
        
        local repo_details=$(invoke_github_api "/repos/$organization/$repo_name" false 50)
        if [[ -z "$repo_details" ]]; then
            continue
        fi
        
        local sec=$(echo "$repo_details" | jq -c '.security_and_analysis // {}')
        
        local has_advanced=$(echo "$sec" | jq -r '.advanced_security.status // "disabled"')
        local has_code_sec=$(echo "$sec" | jq -r '.code_security.status // "disabled"')
        local has_secret=$(echo "$sec" | jq -r '.secret_scanning.status // "disabled"')
        local has_push_prot=$(echo "$sec" | jq -r '.secret_scanning_push_protection.status // "disabled"')
        
        if [[ "$has_advanced" == "enabled" ]] || [[ "$has_code_sec" == "enabled" ]] || \
           [[ "$has_secret" == "enabled" ]] || [[ "$has_push_prot" == "enabled" ]]; then
            
            local adv_sec_status="disabled"
            if [[ "$has_code_sec" != "null" ]]; then
                adv_sec_status="$has_code_sec"
            elif [[ "$has_advanced" != "null" ]]; then
                adv_sec_status="$has_advanced"
            fi
            
            local dependabot_status=$(echo "$sec" | jq -r '.dependabot_security_updates.status // "N/A"')
            local is_private=$(echo "$repo_details" | jq -r '.private')
            local created_at=$(echo "$repo_details" | jq -r '.created_at // ""')
            local updated_at=$(echo "$repo_details" | jq -r '.updated_at // ""')
            local pushed_at=$(echo "$repo_details" | jq -r '.pushed_at // ""')
            
            local repo_obj=$(jq -n \
                --arg repo "$repo_name" \
                --argjson private "$is_private" \
                --arg code_sec "$adv_sec_status" \
                --arg secret "$has_secret" \
                --arg push_prot "$has_push_prot" \
                --arg dependabot "$dependabot_status" \
                --arg created "$created_at" \
                --arg updated "$updated_at" \
                --arg pushed "$pushed_at" \
                '{
                    Repository: $repo,
                    IsPrivate: $private,
                    CodeSecurity: $code_sec,
                    SecretScanning: $secret,
                    SecretScanningPushProtection: $push_prot,
                    DependabotSecurityUpdates: $dependabot,
                    CreatedAt: $created,
                    UpdatedAt: $updated,
                    PushedAt: $pushed
                }')
            
            ghas_enabled_repos=$(echo "$ghas_enabled_repos" | jq --argjson obj "$repo_obj" '. + [$obj]')
        fi
    done < <(echo "$repos" | jq -r '.[].name')
    
    local ghas_count=$(echo "$ghas_enabled_repos" | jq 'length')
    
    jq -n \
        --arg org "$organization" \
        --arg total "$total_repos" \
        --arg ghas "$ghas_count" \
        --argjson repos "$ghas_enabled_repos" \
        '{
            organization: $org,
            total_repositories: ($total | tonumber),
            ghas_enabled_repositories: ($ghas | tonumber),
            repositories: $repos
        }'
}

get_ghas_audit_events() {
    local organization="$1"
    local ghas_repos_json="$2"
    
    local all_events="[]"
    
    local ghas_event_actions=(
        "repo.advanced_security_enabled" "repo.advanced_security_disabled"
        "repository_code_security.enable" "repository_code_security.disable"
        "repository_security_configuration.applied" "repository_security_configuration.removed"
        "repository_secret_scanning.enable" "repository_secret_scanning.disable"
        "repository_secret_scanning_push_protection.enable" "repository_secret_scanning_push_protection.disable"
        "repository_secret_scanning_non_provider_patterns.enabled"
        "repository_secret_scanning_automatic_validity_checks.enabled"
        "repo.secret_scanning_enabled" "repo.secret_scanning_disabled"
        "repo.secret_scanning_push_protection_enabled" "repo.secret_scanning_push_protection_disabled"
        "repository.code_scanning_enabled" "repository.code_scanning_disabled"
        "repo.codeql_enabled" "repo.codeql_disabled"
        "repository.dependabot_alerts_enabled" "repository.dependabot_alerts_disabled"
        "repository.dependabot_security_updates_enabled" "repository.dependabot_security_updates_disabled"
        "repository_vulnerability_alerts.enable" "repository_vulnerability_alerts.disable"
        "repository_vulnerability_alerts_auto_dismissal.enable" "repository_vulnerability_alerts_auto_dismissal.disable"
        "repository_dependency_graph.enable" "repository_dependency_graph.disable"
    )
    
    local actions_filter=$(printf '%s\n' "${ghas_event_actions[@]}" | jq -R . | jq -s .)
    
    local counter=0
    local total_repos=$(echo "$ghas_repos_json" | jq 'length')
    
    while IFS= read -r repo_name; do
        [[ -z "$repo_name" ]] && continue
        
        counter=$((counter + 1))
        
        # Add progress indicator and rate limit check every 20 repos
        if [[ $((counter % 20)) -eq 0 ]]; then
            get_rate_limit_status
            echo -e "${GRAY}  → Audit log progress: $counter/$total_repos repos | Rate limit: ${RATE_LIMIT_INFO[Remaining]}/${RATE_LIMIT_INFO[Limit]}${NC}" >&2
            
            if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 30 ]]; then
                wait_for_rate_limit 30
            fi
        fi
        
        local phrase="repo:$organization/$repo_name"
        local response=$(invoke_github_api "/orgs/$organization/audit-log?phrase=$phrase&per_page=100" false 100)
        local api_result=$?
        
        # Check if API call succeeded and response is valid JSON
        if [[ $api_result -eq 0 ]] && [[ -n "$response" ]] && echo "$response" | jq empty 2>/dev/null; then
            if [[ "$response" != "[]" ]]; then
                local filtered_events=$(echo "$response" | jq --argjson actions "$actions_filter" \
                    '[.[] | select(.action as $a | $actions | index($a) != null)]' 2>/dev/null || echo "[]")
                
                if [[ -n "$filtered_events" ]] && [[ "$filtered_events" != "[]" ]]; then
                    all_events=$(echo "$all_events" | jq --argjson new "$filtered_events" '. + $new' 2>/dev/null || echo "$all_events")
                fi
            fi
        fi
        
    done < <(echo "$ghas_repos_json" | jq -r '.[].Repository // empty')
    
    # Ensure we always return valid JSON
    if ! echo "$all_events" | jq empty 2>/dev/null; then
        echo "[]"
    else
        echo "$all_events"
    fi
}

get_committer_details() {
    local organization="$1"
    local repository="$2"
    local author="$3"
    local ghas_enabled_date="$4"
    
    local first_push=""
    local first_sha=""
    
    # Only query commits if we have a GHAS enabled date
    if [[ -z "$ghas_enabled_date" ]]; then
        jq -n '{FirstPushDateAfterGHAS: "", FirstCommitSHA: ""}'
        return
    fi
    
    local since_param=$(convert_to_iso8601 "$ghas_enabled_date")
    
    if [[ -n "$since_param" ]]; then
        local commits=$(invoke_github_api "/repos/$organization/$repository/commits?author=$author&since=$since_param&per_page=100" false 50 2>&1)
        local api_result=$?
        
        if [[ $api_result -ne 0 ]]; then
            echo -e "${YELLOW}    ⚠ Could not fetch commits for $author in $repository${NC}" >&2
            jq -n '{FirstPushDateAfterGHAS: "", FirstCommitSHA: ""}'
            return
        fi
        
        if [[ -n "$commits" ]] && [[ "$commits" != "[]" ]] && echo "$commits" | jq empty 2>/dev/null; then
            local commit_count=$(echo "$commits" | jq 'length' 2>/dev/null || echo "0")
            
            if [[ $commit_count -gt 0 ]]; then
                local first_commit=$(echo "$commits" | jq -r 'sort_by(.commit.author.date) | first' 2>/dev/null)
                
                if [[ "$first_commit" != "null" ]] && [[ -n "$first_commit" ]]; then
                    local commit_date=$(echo "$first_commit" | jq -r '.commit.author.date' 2>/dev/null)
                    first_push=$(date -d "$commit_date" '+%Y-%m-%d' 2>/dev/null || \
                               date -j -f "%Y-%m-%dT%H:%M:%SZ" "$commit_date" '+%Y-%m-%d' 2>/dev/null || \
                               echo "$commit_date")
                    first_sha=$(echo "$first_commit" | jq -r '.sha' 2>/dev/null)
                fi
            fi
        fi
    fi
    
    jq -n \
        --arg push "$first_push" \
        --arg sha "$first_sha" \
        '{FirstPushDateAfterGHAS: $push, FirstCommitSHA: $sha}'
}

# ============================================================================
# BANNER & SETUP
# ============================================================================

echo ""
echo -e "${CYAN}GHAS Audit Report${NC}"
echo -e "${WHITE}Organization: $ORGANIZATION${NC}"
echo -e "${WHITE}Output Path: $OUTPUT_PATH${NC}"

# Show optional parameters status
echo ""
echo -e "${WHITE}Report Options:${NC}"
echo -e "${GRAY}  Base reports: Always included (licenses, committers summary)${NC}"
if [[ "$DETAILED_AUDIT" == "true" ]]; then
    echo -e "${GREEN}  Audit Mode: DETAILED (includes repository details, features, and commit details)${NC}"
else
    echo -e "${DARKGRAY}  Audit Mode: BASIC (use -d or --detailed-audit for complete audit)${NC}"
fi
echo ""

# ============================================================================
# PREREQUISITES CHECK
# ============================================================================

# Run prerequisites check before starting audit
if ! test_prerequisites "$ORGANIZATION"; then
    exit 1
fi

# ============================================================================
# AUDIT EXECUTION
# ============================================================================

# Check initial rate limit status
echo -e "${GRAY}Checking GitHub API rate limit...${NC}"
get_rate_limit_status
echo -e "${WHITE}  Rate limit: ${RATE_LIMIT_INFO[Remaining]}/${RATE_LIMIT_INFO[Limit]} requests remaining${NC}"
if [[ ${RATE_LIMIT_INFO[Reset]} -gt 0 ]]; then
    reset_time=$(date -d "@${RATE_LIMIT_INFO[Reset]}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
                      date -r "${RATE_LIMIT_INFO[Reset]}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    echo -e "${WHITE}  Resets at: $reset_time${NC}"
fi
echo ""

# Create output directory
mkdir -p "$OUTPUT_PATH"

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
REPORT_DIR="$OUTPUT_PATH/$ORGANIZATION-$TIMESTAMP"
mkdir -p "$REPORT_DIR"
echo -e "${CYAN}Report directory: $REPORT_DIR${NC}"
echo ""

# ============================================================================
# STEP 1: Billing Information
# ============================================================================
echo -e "${YELLOW}[1/5] Retrieving Billing Data...${NC}"

BILLING_DATA=$(get_ghas_billing_info "$ORGANIZATION")

if [[ -n "$BILLING_DATA" ]]; then
    CODE_SEC_COMMITTERS=$(echo "$BILLING_DATA" | jq -r '.code_security_committers // 0')
    SECRET_PROT_COMMITTERS=$(echo "$BILLING_DATA" | jq -r '.secret_protection_committers // 0')
    echo -e "${GREEN}  ✓ Code Security: $CODE_SEC_COMMITTERS committers | Secret Protection: $SECRET_PROT_COMMITTERS committers${NC}"
else
    echo -e "${RED}  Error retrieving billing data${NC}"
fi
echo ""

# Build list of GHAS repositories from billing data
GHAS_REPOS="[]"
if [[ $(echo "$BILLING_DATA" | jq '.repositories | length') -gt 0 ]]; then
    GHAS_REPOS=$(echo "$BILLING_DATA" | jq -c '[.repositories[] | {Repository: (.name | split("/") | last)}]')
fi

# ============================================================================
# STEP 2: Audit Log
# ============================================================================
echo -e "${YELLOW}[2/5] Retrieving Audit Log...${NC}"

AUDIT_LOG_DATA="[]"

if [[ $(echo "$GHAS_REPOS" | jq 'length' 2>/dev/null || echo "0") -gt 0 ]]; then
    if AUDIT_LOG_DATA=$(get_ghas_audit_events "$ORGANIZATION" "$GHAS_REPOS" 2>&1); then
        if echo "$AUDIT_LOG_DATA" | jq empty 2>/dev/null; then
            AUDIT_COUNT=$(echo "$AUDIT_LOG_DATA" | jq 'length' 2>/dev/null || echo "0")
            if [[ $AUDIT_COUNT -gt 0 ]]; then
                echo -e "${GREEN}  ✓ Audit log retrieval completed: $AUDIT_COUNT total events${NC}"
            else
                echo -e "${YELLOW}  ⚠ No GHAS audit events found${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ Invalid audit log data received${NC}"
            echo -e "${GRAY}    Continuing without audit log data...${NC}"
            AUDIT_LOG_DATA="[]"
        fi
    else
        echo -e "${YELLOW}  ⚠ Audit log not available${NC}"
        AUDIT_LOG_DATA="[]"
    fi
else
    echo -e "${YELLOW}  ⚠ No GHAS repositories found to query audit log${NC}"
fi
echo ""

# ============================================================================
# STEP 3: Optional - Repository Details
# ============================================================================
declare -A REPOSITORY_DETAILS

if [[ "$DETAILED_AUDIT" == "true" ]]; then
    echo -e "${YELLOW}[3/5] Retrieving Repository Details (detailed audit)...${NC}"
    
    # Extract repo names into array
    mapfile -t repo_names < <(echo "$GHAS_REPOS" | jq -r '.[].Repository')
    
    if [[ ${#repo_names[@]} -gt 0 ]]; then
        DETAILS_JSON=$(get_repository_details "$ORGANIZATION" "${repo_names[@]}")
        
        # Convert JSON to associative array
        while IFS= read -r key; do
            REPOSITORY_DETAILS["$key"]=$(echo "$DETAILS_JSON" | jq -c ".\"$key\"")
        done < <(echo "$DETAILS_JSON" | jq -r 'keys[]')
        
        echo -e "${GREEN}  ✓ Repository details retrieved for ${#REPOSITORY_DETAILS[@]} repositories${NC}"
    fi
    echo ""
else
    echo -e "${DARKGRAY}[3/5] Skipping Repository Details (use -d or --detailed-audit to enable)${NC}"
    echo ""
fi

# ============================================================================
# STEP 4: Optional - Repository Features
# ============================================================================
declare -A REPOSITORY_FEATURES

if [[ "$DETAILED_AUDIT" == "true" ]]; then
    echo -e "${YELLOW}[4/5] Retrieving Repository Features (detailed audit)...${NC}"
    
    # Extract repo names into array
    mapfile -t repo_names < <(echo "$GHAS_REPOS" | jq -r '.[].Repository')
    
    if [[ ${#repo_names[@]} -gt 0 ]]; then
        FEATURES_JSON=$(get_repository_features "$ORGANIZATION" "${repo_names[@]}")
        
        # Convert JSON to associative array
        while IFS= read -r key; do
            REPOSITORY_FEATURES["$key"]=$(echo "$FEATURES_JSON" | jq -c ".\"$key\"")
        done < <(echo "$FEATURES_JSON" | jq -r 'keys[]')
        
        echo -e "${GREEN}  ✓ Repository features retrieved for ${#REPOSITORY_FEATURES[@]} repositories${NC}"
    fi
    echo ""
else
    echo -e "${DARKGRAY}[4/5] Skipping Repository Features (use -d or --detailed-audit to enable)${NC}"
    echo ""
fi

# ============================================================================
# STEP 5: Generate Reports
# ============================================================================
echo -e "${YELLOW}[5/5] Generating Reports...${NC}"

# Process audit logs
declare -A REPO_AUDIT_EVENTS
AUDIT_LOG_SUMMARY="[]"

while IFS= read -r event; do
    [[ -z "$event" ]] && continue
    
    RAW_REPO_NAME=$(echo "$event" | jq -r '.repo // .data.repo // ""')
    REPO_NAME=$(get_normalized_repo_name "$RAW_REPO_NAME")
    
    TIMESTAMP=$(echo "$event" | jq -r '.created_at // .["@timestamp"] // 0')
    ACTION=$(echo "$event" | jq -r '.action // ""')
    ACTOR=$(echo "$event" | jq -r '.actor // ""')
    
    FORMATTED_TIMESTAMP=$(convert_to_formatted_timestamp "$TIMESTAMP")
    
    CONFIG_METHOD=""
    if [[ "$ACTION" == "repository_security_configuration.applied" ]]; then
        CONFIG_METHOD="Policy"
    elif [[ "$ACTION" =~ repository_code_security|repository_secret_scanning|repo.advanced_security_enabled ]]; then
        CONFIG_METHOD="Manual"
    fi
    
    EVENT_TYPE="OTHER"
    if [[ "$ACTION" =~ advanced_security ]]; then
        EVENT_TYPE="GHAS"
    elif [[ "$ACTION" =~ secret_scanning ]]; then
        EVENT_TYPE="SECRET_SCANNING"
    elif [[ "$ACTION" =~ code_scanning ]]; then
        EVENT_TYPE="CODE_SCANNING"
    elif [[ "$ACTION" =~ dependabot ]]; then
        EVENT_TYPE="DEPENDABOT"
    elif [[ "$ACTION" =~ vulnerability ]]; then
        EVENT_TYPE="VULNERABILITY"
    elif [[ "$ACTION" =~ security ]]; then
        EVENT_TYPE="SECURITY"
    fi
    
    SECURITY_CONFIG_NAME=$(echo "$event" | jq -r '.security_configuration_name // ""')
    
    SIMPLIFIED_EVENT=$(jq -n \
        --arg repo "$REPO_NAME" \
        --arg action "$ACTION" \
        --arg actor "$ACTOR" \
        --arg ts "$FORMATTED_TIMESTAMP" \
        --arg config_name "$SECURITY_CONFIG_NAME" \
        --arg config_method "$CONFIG_METHOD" \
        --arg event_type "$EVENT_TYPE" \
        '{
            Repository: $repo,
            Action: $action,
            Actor: $actor,
            Timestamp: $ts,
            SecurityConfigurationName: $config_name,
            ConfigurationMethod: $config_method,
            EventType: $event_type
        }')
    
    AUDIT_LOG_SUMMARY=$(echo "$AUDIT_LOG_SUMMARY" | jq --argjson evt "$SIMPLIFIED_EVENT" '. + [$evt]')
    
    if [[ -n "$REPO_NAME" ]]; then
        if [[ -z "${REPO_AUDIT_EVENTS[$REPO_NAME]}" ]]; then
            REPO_AUDIT_EVENTS[$REPO_NAME]="[]"
        fi
        REPO_AUDIT_EVENTS[$REPO_NAME]=$(echo "${REPO_AUDIT_EVENTS[$REPO_NAME]}" | jq --argjson evt "$SIMPLIFIED_EVENT" '. + [$evt]')
    fi
done < <(echo "$AUDIT_LOG_DATA" | jq -c '.[]')

# Complete Report JSON
REPOS_WITH_ACTIVE=$(echo "$BILLING_DATA" | jq -r '.total_count // 0')
CODE_SEC_REPOS=$(echo "$BILLING_DATA" | jq -r '.code_security_repositories // 0')
SECRET_PROT_REPOS=$(echo "$BILLING_DATA" | jq -r '.secret_protection_repositories // 0')
MAX_COMMITTERS=$(echo "$BILLING_DATA" | jq -r '.maximum_advanced_security_committers // 0')
PURCHASED_LICENSES=$(echo "$BILLING_DATA" | jq -r '.purchased_advanced_security_committers // 0')
AUDIT_EVENTS_COUNT=$(echo "$AUDIT_LOG_DATA" | jq 'length')

# Build generated files list
GENERATED_FILES_JSON=$(jq -n '{
    CSV: ["ghas-licensing.csv", "active-committers.csv"],
    JSON: ["summary-report.json", "audit-log.json"]
}')

if [[ "$DETAILED_AUDIT" == "true" ]]; then
    GENERATED_FILES_JSON=$(echo "$GENERATED_FILES_JSON" | jq '.CSV += ["repositories-metadata.csv", "repositories-features.csv", "active-committers-detailed.csv"]')
fi

COMPLETE_REPORT=$(jq -n \
    --arg org "$ORGANIZATION" \
    --arg date "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg repos_active "$REPOS_WITH_ACTIVE" \
    --arg code_comm "$CODE_SEC_COMMITTERS" \
    --arg code_repos "$CODE_SEC_REPOS" \
    --arg secret_comm "$SECRET_PROT_COMMITTERS" \
    --arg secret_repos "$SECRET_PROT_REPOS" \
    --arg purchased "$PURCHASED_LICENSES" \
    --arg max_comm "$MAX_COMMITTERS" \
    --arg audit_count "$AUDIT_EVENTS_COUNT" \
    --argjson files "$GENERATED_FILES_JSON" \
    '{
        Organization: $org,
        ReportDate: $date,
        Summary: {
            RepositoriesWithActiveCommitters: ($repos_active | tonumber),
            CodeSecurityCommitters: ($code_comm | tonumber),
            CodeSecurityRepositories: ($code_repos | tonumber),
            SecretProtectionCommitters: ($secret_comm | tonumber),
            SecretProtectionRepositories: ($secret_repos | tonumber),
            MeteredLicensesPurchased: ($purchased | tonumber),
            MaximumCommittersAllowed: ($max_comm | tonumber),
            AuditEventsFound: ($audit_count | tonumber)
        },
        GeneratedFiles: $files
    }')

echo "$COMPLETE_REPORT" | jq '.' > "$REPORT_DIR/summary-report.json"
echo -e "${GREEN}  ✓ summary-report.json${NC}"

# Audit Log JSON
if [[ $(echo "$AUDIT_LOG_SUMMARY" | jq 'length') -gt 0 ]]; then
    EVENT_TYPES=$(echo "$AUDIT_LOG_SUMMARY" | jq -c '[group_by(.EventType)[] | {Type: .[0].EventType, Count: length}]')
    
    AUDIT_REPORT=$(jq -n \
        --arg org "$ORGANIZATION" \
        --arg date "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        --arg count "$(echo "$AUDIT_LOG_SUMMARY" | jq 'length')" \
        --argjson types "$EVENT_TYPES" \
        --argjson events "$AUDIT_LOG_SUMMARY" \
        '{
            Organization: $org,
            ReportDate: $date,
            TotalEvents: ($count | tonumber),
            EventTypes: $types,
            Events: $events
        }')
    
    echo "$AUDIT_REPORT" | jq '.' > "$REPORT_DIR/audit-log.json"
    EVENT_COUNT=$(echo "$AUDIT_LOG_SUMMARY" | jq 'length')
    echo -e "${GREEN}  ✓ audit-log.json ($EVENT_COUNT events)${NC}"
fi

# Build repository committers map and determine CodeSecurity/SecretProtection
declare -A REPO_COMMITTERS
declare -A REPO_CODE_SECURITY
declare -A REPO_SECRET_PROTECTION
declare -A REPO_GHAS_ENABLED_DATES

while IFS= read -r repo_json; do
    [[ -z "$repo_json" ]] && continue
    
    REPO_NAME=$(echo "$repo_json" | jq -r '.name' | xargs basename)
    
    # Determine product type
    PRODUCT_TYPE=$(echo "$repo_json" | jq -r '.product_type // ""')
    PRODUCT_TYPE_ADDITIONAL=$(echo "$repo_json" | jq -r '.product_type_additional // ""')
    
    if [[ "$PRODUCT_TYPE" == "code_security" ]] || [[ "$PRODUCT_TYPE_ADDITIONAL" == "code_security" ]]; then
        REPO_CODE_SECURITY[$REPO_NAME]="enabled"
    fi
    if [[ "$PRODUCT_TYPE" == "secret_protection" ]] || [[ "$PRODUCT_TYPE_ADDITIONAL" == "secret_protection" ]]; then
        REPO_SECRET_PROTECTION[$REPO_NAME]="enabled"
    fi
    
    # Build committers
    COMMITTERS="[]"
    
    while IFS= read -r committer_json; do
        [[ -z "$committer_json" ]] && continue
        
        USERNAME=$(echo "$committer_json" | jq -r '.user_login // ""')
        EMAIL=$(echo "$committer_json" | jq -r '.last_pushed_email // ""')
        LAST_PUSHED=$(echo "$committer_json" | jq -r '.last_pushed_date // ""')
        
        COMMITTER_OBJ=$(jq -n \
            --arg user "$USERNAME" \
            --arg email "$EMAIL" \
            --arg pushed "$LAST_PUSHED" \
            '{Username: $user, Email: $email, LastPushedDate: $pushed}')
        
        COMMITTERS=$(echo "$COMMITTERS" | jq --argjson c "$COMMITTER_OBJ" '. + [$c]')
    done < <(echo "$repo_json" | jq -c '.advanced_security_committers_breakdown[]? // empty')
    
    REPO_COMMITTERS[$REPO_NAME]="$COMMITTERS"
done < <(echo "$BILLING_DATA" | jq -c '.repositories[]? // empty')

# ghas-licensing.csv (base report - always generated)
LICENSES_DATA="[]"

for REPO_NAME in "${!REPO_COMMITTERS[@]}"; do
    COMMITTER_COUNT=$(echo "${REPO_COMMITTERS[$REPO_NAME]}" | jq 'length')
    
    ENABLED_BY=""
    ENABLED_AT=""
    CONFIG_METHOD=""
    POLICY_NAME=""
    
    if [[ -n "${REPO_AUDIT_EVENTS[$REPO_NAME]}" ]]; then
        FIRST_EVENT=$(get_first_enable_event "${REPO_AUDIT_EVENTS[$REPO_NAME]}")
        
        if [[ "$FIRST_EVENT" != "null" ]]; then
            ENABLED_BY=$(echo "$FIRST_EVENT" | jq -r '.Actor // ""')
            ENABLED_AT=$(echo "$FIRST_EVENT" | jq -r '.Timestamp // ""')
            CONFIG_METHOD=$(echo "$FIRST_EVENT" | jq -r '.ConfigurationMethod // ""')
            POLICY_NAME=$(echo "$FIRST_EVENT" | jq -r '.SecurityConfigurationName // ""')
            REPO_GHAS_ENABLED_DATES[$REPO_NAME]="$ENABLED_AT"
        fi
    fi
    
    HAS_CODE_SECURITY="disabled"
    if [[ -n "${REPO_CODE_SECURITY[$REPO_NAME]}" ]]; then
        HAS_CODE_SECURITY="enabled"
    fi
    
    HAS_SECRET_PROTECTION="disabled"
    if [[ -n "${REPO_SECRET_PROTECTION[$REPO_NAME]}" ]]; then
        HAS_SECRET_PROTECTION="enabled"
    fi
    
    ROW=$(jq -n \
        --arg repo "$REPO_NAME" \
        --arg code_sec "$HAS_CODE_SECURITY" \
        --arg secret_prot "$HAS_SECRET_PROTECTION" \
        --arg enabled_by "$ENABLED_BY" \
        --arg enabled_at "$ENABLED_AT" \
        --arg config_method "$CONFIG_METHOD" \
        --arg policy "$POLICY_NAME" \
        --arg committers "$COMMITTER_COUNT" \
        '{
            Repository: $repo,
            CodeSecurity: $code_sec,
            SecretProtection: $secret_prot,
            GHASEnabledBy: $enabled_by,
            GHASEnabledAt: $enabled_at,
            GHASConfigurationMethod: $config_method,
            GHASPolicyName: $policy,
            ActiveCommittersCount: ($committers | tonumber)
        }')
    
    LICENSES_DATA=$(echo "$LICENSES_DATA" | jq --argjson row "$ROW" '. + [$row]')
done

LICENSES_CSV="$REPORT_DIR/ghas-licensing.csv"
echo "$LICENSES_DATA" | jq -r 'sort_by(.Repository) | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' > "$LICENSES_CSV"
LICENSES_COUNT=$(echo "$LICENSES_DATA" | jq 'length')
echo -e "${GREEN}  ✓ ghas-licensing.csv ($LICENSES_COUNT repos)${NC}"

# repositories-metadata.csv (optional - requires DETAILED_AUDIT)
if [[ "$DETAILED_AUDIT" == "true" ]] && [[ ${#REPOSITORY_DETAILS[@]} -gt 0 ]]; then
    DETAILS_DATA="[]"
    
    for REPO_NAME in "${!REPOSITORY_DETAILS[@]}"; do
        DETAIL_JSON="${REPOSITORY_DETAILS[$REPO_NAME]}"
        CREATED_AT=$(echo "$DETAIL_JSON" | jq -r '.CreatedAt')
        CREATED_ISO=$(convert_to_iso8601 "$CREATED_AT")
        
        ROW=$(echo "$DETAIL_JSON" | jq --arg created "$CREATED_ISO" '. + {CreatedAt: $created}')
        DETAILS_DATA=$(echo "$DETAILS_DATA" | jq --argjson row "$ROW" '. + [$row]')
    done
    
    DETAILS_CSV="$REPORT_DIR/repositories-metadata.csv"
    echo "$DETAILS_DATA" | jq -r 'sort_by(.Repository) | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' > "$DETAILS_CSV"
    DETAILS_COUNT=$(echo "$DETAILS_DATA" | jq 'length')
    echo -e "${GREEN}  ✓ repositories-metadata.csv ($DETAILS_COUNT repos)${NC}"
fi

# repositories-features.csv (optional - requires DETAILED_AUDIT)
if [[ "$DETAILED_AUDIT" == "true" ]] && [[ ${#REPOSITORY_FEATURES[@]} -gt 0 ]]; then
    FEATURES_DATA="[]"
    
    for REPO_NAME in "${!REPOSITORY_FEATURES[@]}"; do
        FEATURE_JSON="${REPOSITORY_FEATURES[$REPO_NAME]}"
        FEATURES_DATA=$(echo "$FEATURES_DATA" | jq --argjson row "$FEATURE_JSON" '. + [$row]')
    done
    
    FEATURES_CSV="$REPORT_DIR/repositories-features.csv"
    echo "$FEATURES_DATA" | jq -r 'sort_by(.Repository) | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' > "$FEATURES_CSV"
    FEATURES_COUNT=$(echo "$FEATURES_DATA" | jq 'length')
    echo -e "${GREEN}  ✓ repositories-features.csv ($FEATURES_COUNT repos)${NC}"
fi

# active-committers.csv (always generated - summary)
declare -A UNIQUE_COMMITTERS

for REPO_NAME in "${!REPO_COMMITTERS[@]}"; do
    COMMITTERS="${REPO_COMMITTERS[$REPO_NAME]}"
    while IFS= read -r committer_json; do
        [[ -z "$committer_json" ]] && continue
        
        USERNAME=$(echo "$committer_json" | jq -r '.Username')
        EMAIL=$(echo "$committer_json" | jq -r '.Email')
        
        if [[ -z "${UNIQUE_COMMITTERS[$USERNAME]}" ]]; then
            UNIQUE_COMMITTERS[$USERNAME]=$(jq -n --arg email "$EMAIL" --arg repos "$REPO_NAME" '{Email: $email, Repositories: [$repos]}')
        else
            EXISTING=$(echo "${UNIQUE_COMMITTERS[$USERNAME]}" | jq --arg repo "$REPO_NAME" '.Repositories += [$repo]')
            UNIQUE_COMMITTERS[$USERNAME]="$EXISTING"
        fi
    done < <(echo "$COMMITTERS" | jq -c '.[]')
done

COMMITTERS_SUMMARY="[]"
for USERNAME in "${!UNIQUE_COMMITTERS[@]}"; do
    USER_DATA="${UNIQUE_COMMITTERS[$USERNAME]}"
    EMAIL=$(echo "$USER_DATA" | jq -r '.Email')
    REPO_COUNT=$(echo "$USER_DATA" | jq '.Repositories | length')
    REPO_LIST=$(echo "$USER_DATA" | jq -r '.Repositories | join("; ")')
    
    ROW=$(jq -n \
        --arg user "$USERNAME" \
        --arg email "$EMAIL" \
        --arg count "$REPO_COUNT" \
        --arg list "$REPO_LIST" \
        '{
            Username: $user,
            Email: $email,
            TotalRepositories: ($count | tonumber),
            RepositoryList: $list
        }')
    
    COMMITTERS_SUMMARY=$(echo "$COMMITTERS_SUMMARY" | jq --argjson row "$ROW" '. + [$row]')
done

COMMITTERS_CSV="$REPORT_DIR/active-committers.csv"
echo "$COMMITTERS_SUMMARY" | jq -r 'sort_by(.Username) | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' > "$COMMITTERS_CSV"
COMMITTERS_COUNT=$(echo "$COMMITTERS_SUMMARY" | jq 'length')
echo -e "${GREEN}  ✓ active-committers.csv ($COMMITTERS_COUNT unique committers)${NC}"

# active-committers-detailed.csv (optional - requires DETAILED_AUDIT)
if [[ "$DETAILED_AUDIT" == "true" ]]; then
    TOTAL_COMMITTERS=0
    for REPO_NAME in "${!REPO_COMMITTERS[@]}"; do
        COMMITTERS="${REPO_COMMITTERS[$REPO_NAME]}"
        TOTAL_COMMITTERS=$((TOTAL_COMMITTERS + $(echo "$COMMITTERS" | jq 'length')))
    done
    
    echo -e "${GRAY}  Processing commit details for $TOTAL_COMMITTERS committers (this may take a while)...${NC}"
    
    DETAILED_COMMITTERS="[]"
    COMMITTER_INDEX=0
    
    for REPO_NAME in "${!REPO_COMMITTERS[@]}"; do
        COMMITTERS="${REPO_COMMITTERS[$REPO_NAME]}"
        
        if [[ $(echo "$COMMITTERS" | jq 'length') -gt 0 ]]; then
            GHAS_ENABLED_DATE="${REPO_GHAS_ENABLED_DATES[$REPO_NAME]:-}"
            
            echo -e "${GRAY}  → Processing $(echo "$COMMITTERS" | jq 'length') committers for $REPO_NAME...${NC}"
            
            while IFS= read -r committer_json; do
                [[ -z "$committer_json" ]] && continue
                
                COMMITTER_INDEX=$((COMMITTER_INDEX + 1))
                
                if [[ $((COMMITTER_INDEX % 10)) -eq 0 ]]; then
                    echo -e "${DARKGRAY}     Progress: $COMMITTER_INDEX/$TOTAL_COMMITTERS committers${NC}"
                fi
                
                # Check rate limit every 50 committers
                if [[ $((COMMITTER_INDEX % 50)) -eq 0 ]]; then
                    get_rate_limit_status
                    if [[ ${RATE_LIMIT_INFO[Remaining]} -lt 30 ]]; then
                        wait_for_rate_limit 30
                    fi
                fi
                
                USERNAME=$(echo "$committer_json" | jq -r '.Username')
                EMAIL=$(echo "$committer_json" | jq -r '.Email')
                LAST_PUSHED=$(echo "$committer_json" | jq -r '.LastPushedDate')
                
                DETAILS=$(get_committer_details "$ORGANIZATION" "$REPO_NAME" "$USERNAME" "$GHAS_ENABLED_DATE")
                
                FIRST_PUSH_AFTER=$(echo "$DETAILS" | jq -r '.FirstPushDateAfterGHAS')
                FIRST_SHA=$(echo "$DETAILS" | jq -r '.FirstCommitSHA')
                
                GHAS_DATE_FORMATTED=""
                if [[ -n "$GHAS_ENABLED_DATE" ]]; then
                    GHAS_DATE_FORMATTED=$(date -d "$GHAS_ENABLED_DATE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
                                        date -j -f "%Y-%m-%d %H:%M:%S" "$GHAS_ENABLED_DATE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
                                        echo "$GHAS_ENABLED_DATE")
                fi
                
                ROW=$(jq -n \
                    --arg repo "$REPO_NAME" \
                    --arg user "$USERNAME" \
                    --arg email "$EMAIL" \
                    --arg last_pushed "$LAST_PUSHED" \
                    --arg ghas_date "$GHAS_DATE_FORMATTED" \
                    --arg first_push "$FIRST_PUSH_AFTER" \
                    --arg first_sha "$FIRST_SHA" \
                    '{
                        Repository: $repo,
                        Username: $user,
                        Email: $email,
                        LastPushedDate: $last_pushed,
                        GHASEnabledDate: $ghas_date,
                        FirstPushDateAfterGHAS: $first_push,
                        FirstCommitSHA: $first_sha
                    }')
                
                DETAILED_COMMITTERS=$(echo "$DETAILED_COMMITTERS" | jq --argjson row "$ROW" '. + [$row]')
            done < <(echo "$COMMITTERS" | jq -c '.[]')
        fi
    done
    
    if [[ $(echo "$DETAILED_COMMITTERS" | jq 'length') -gt 0 ]]; then
        DETAILED_CSV="$REPORT_DIR/active-committers-detailed.csv"
        echo "$DETAILED_COMMITTERS" | jq -r 'sort_by(.Username, .Repository) | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' > "$DETAILED_CSV"
        DETAILED_COUNT=$(echo "$DETAILED_COMMITTERS" | jq 'length')
        echo -e "${GREEN}  ✓ active-committers-detailed.csv ($DETAILED_COUNT user-repository combinations)${NC}"
    fi
fi

echo ""

# ============================================================================
# Final Summary
# ============================================================================
echo -e "${GREEN}Report completed!${NC}"
echo -e "${WHITE}  Organization: $ORGANIZATION${NC}"
echo -e "${WHITE}  Repositories with Active Committers: $REPOS_WITH_ACTIVE${NC}"
echo -e "${GRAY}    - Code Security: $CODE_SEC_COMMITTERS committers in $CODE_SEC_REPOS repositories${NC}"
echo -e "${GRAY}    - Secret Protection: $SECRET_PROT_COMMITTERS committers in $SECRET_PROT_REPOS repositories${NC}"
echo -e "${CYAN}  Output: $REPORT_DIR${NC}"

# Show optional reports status
if [[ "$DETAILED_AUDIT" == "true" ]]; then
    echo ""
    echo -e "${WHITE}  Detailed Audit included:${NC}"
    echo -e "${GREEN}    ✓ Repository Details${NC}"
    echo -e "${GREEN}    ✓ Repository Features${NC}"
    echo -e "${GREEN}    ✓ Commit Details${NC}"
fi

echo ""

# Final rate limit status
get_rate_limit_status
echo -e "${CYAN}GitHub API Rate Limit Status:${NC}"
echo -e "${WHITE}  Requests used (total session): ${RATE_LIMIT_INFO[Used]}${NC}"
echo -e "${WHITE}  Requests remaining: ${RATE_LIMIT_INFO[Remaining]}/${RATE_LIMIT_INFO[Limit]}${NC}"
if [[ ${RATE_LIMIT_INFO[Reset]} -gt 0 ]]; then
    reset_time=$(date -d "@${RATE_LIMIT_INFO[Reset]}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
                      date -r "${RATE_LIMIT_INFO[Reset]}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    echo -e "${WHITE}  Next reset: $reset_time${NC}"
fi
echo ""

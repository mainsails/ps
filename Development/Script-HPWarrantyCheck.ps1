$serial = ''
$partnumber = ''
$csv = '' # columns sn/pn


$apiKey = '' # https://developers.hp.com/
$apiSecret = ''
$apiURL = 'https://css.api.hp.com'

$authKey = Invoke-WebRequest -Method POST -Uri "$apiURL/oauth/v1/token" -Body "apiKey=$apiKey&apiSecret=$apiSecret&grantType=client_credentials&scope=warranty"
[xml]$Content = $authKey.Content
[string]$AccessToken = $Content.root.access_token | Out-String

$headers = @{}
$headers.add("Authorization","Bearer $AccessToken")
$headers.add("accept","application/json")
$headers.add("content-type","application/json")



# Query by Serial and Part Number - max 5 devices
$body = "[{ `"sn`": `"$serial`" }]"
$results = Invoke-WebRequest -Method Post -Uri "$apiURL/productWarranty/v1/queries" -Headers $headers -Body $body
$results.Content | ConvertFrom-Json

# Query by Serial and Part Number - max 5 devices
$body = "[{ `"sn`": `"$serial`", `"pn`": `"$partnumber`" }]"
$results = Invoke-WebRequest -Method Post -Uri "$apiURL/productWarranty/v1/queries" -Headers $headers -Body $body
$results.Content | ConvertFrom-Json

# Job by Serial and Part Number - max 5000 devices

$body = $data | ConvertTo-Json
$results = Invoke-WebRequest -Method Post -Uri "$apiURL/productWarranty/v1/jobs" -Headers $headers -Body $body
$job = $results.Content | ConvertFrom-Json
$status = Invoke-WebRequest -Method Get -Uri "$apiURL/productWarranty/v1/jobs/$($job.jobId)" -Headers $headers
# wait ?
If ($status.StatusCode -eq 200) {
    $results = Invoke-WebRequest -Method Get -Uri "$apiURL/productWarranty/v1/jobs/$($job.jobId)/results" -Headers $headers
    $results.Content | ConvertFrom-Json
}
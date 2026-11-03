# Plans the bucket policies offline. `terraform validate` cannot catch an
# expression that fails only once each bucket key is known, so this plans
# every bucket and checks the D-071 Forms gates land on the Forms bucket only.
mock_provider "aws" {
  override_during = plan
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::uid-portal-at-mock", id = "uid-portal-at-mock" }
  }
}

variables {
  upload_bucket_name   = "uid-portal-at-uploads"
  download_bucket_name = "uid-portal-at-downloads"
  artifact_bucket_name = "uid-portal-at-artifacts"
  forms_bucket_name    = "uid-portal-at-forms"
  browser_origins      = ["https://forms.at.insureu.uid.utah.gov"]
  kms_key_arn          = null
  existing_bucket_names = {
    uploads   = ""
    downloads = ""
    artifacts = ""
  }
}

run "forms_bucket_gets_every_scan_gate" {
  command = plan

  variables {
    forms_scan_gated_principal_arns = ["arn:aws:iam::705157108110:role/uid-portal-at-forms_pdf_worker"]
    forms_malware_scan_role_arn     = "arn:aws:iam::705157108110:role/uid-insureu-at-forms-malware-scan"
  }

  assert {
    condition = [for s in jsondecode(aws_s3_bucket_policy.tls_only["forms"].policy).Statement : s.Sid] == [
      "DenyInsecureTransport",
      "DenyUnscannedFormsLinks",
      "DenyUnscannedFormsReads",
      "OnlyTheScannerTagsScanStatus",
    ]
    error_message = "The Forms bucket policy must carry TLS plus all three scan gates."
  }

  assert {
    condition = alltrue([
      for k in ["uploads", "downloads", "artifacts"] :
      [for s in jsondecode(aws_s3_bucket_policy.tls_only[k].policy).Statement : s.Sid] == ["DenyInsecureTransport"]
    ])
    error_message = "Only the Forms bucket may carry the scan gates."
  }
}

run "optional_gates_stay_off_until_configured" {
  command = plan

  assert {
    condition = [for s in jsondecode(aws_s3_bucket_policy.tls_only["forms"].policy).Statement : s.Sid] == [
      "DenyInsecureTransport",
      "DenyUnscannedFormsLinks",
    ]
    error_message = "Without gated principals or a scanner role, only the link gate applies."
  }
}

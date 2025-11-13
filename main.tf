provider "aws" {
  region = "eu-west-2" #london region
}
resource "aws_s3_bucket" "terraform-today1"{
    bucket = "terraform-today1"
}
terraform {
  backend "s3" {
    #replace this with your bucket name!
    bucket        = "terraform-today1"
    key           = "global/s3/terraform.tfstate"
    region        = "eu-west-2"
  }
}
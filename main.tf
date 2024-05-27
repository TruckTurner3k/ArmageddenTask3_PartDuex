/*You must complete the following scenerio.


A) European gaming company is moving to GCP. It has the following requirements in
it's first stage migration to the Cloud:


A) You must choose a region in Europe to host it's prototype gaming information.  
This page must only be on a RFC 1918 Private 10 net and can't be accessible from the Internet.


B) The Americas must have 2 regions and both must be RFC 1918 172.16 based subnets.  
They can peer with HQ in order to view the homepage however, they can only view the page on port 80.


C) Asia Pacific region must be choosen and it must be a RFC 1918 192.168 based subnet.  
This subnet can only VPN into HQ.  Additionally, only port 3389 is open to Asia. No 80, no 22.


Deliverables.
1) Complete Terraform for the entire solution.
2) Git Push of the solution to your GitHub.
3) Screenshots showing how the HQ homepage was accessed from both the Americas and Asia Pacific.*/




terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "5.27.0"
    }
  }
}
provider "google" {
  credentials = file ("carbon-sensor-419900-86735cb739be.json")
  project     = "carbon-sensor-419900"
  region      = "us-central1"
}
#############################################
#CREATE 1 VPC & 4 SUBNETS w/ Firewall Rules #
#############################################


resource "google_compute_network" "narrowpath" {
  name                    = "thenarrowpath"
  routing_mode            = "REGIONAL"
  auto_create_subnetworks = false
}


# This is HQ, page only on RFC 1918 Private 10 and no access to internet
resource "google_compute_subnetwork" "narrowpath_subnet1" {
  name          = "narrowsub1"
  description   = "Finland-European Gaming Company"  
  ip_cidr_range = "10.17.1.0/24" #must be private
  region        = "europe-north1"
  private_ip_google_access = true
  network       = google_compute_network.narrowpath.id
}


# example resource "google_compute_instance" "name" {
 


# 2 Americas RFC 1918 172.16 Subnets, peering only on port 80
resource "google_compute_subnetwork" "narrowpath_subnet2" {
  name          = "narrowsub2"
  description   = "North America-SouthCarolina"
  ip_cidr_range = "172.16.7.0/24" #
  region        = "us-east1"
  network       = google_compute_network.narrowpath.id
}


resource "google_compute_subnetwork" "narrowpath_subnet3" {
  name          = "narrowsub3"
  description   = "South America-Sao Paulo"
  ip_cidr_range = "172.16.9.0/24"
  region        = "southamerica-east1"
  network       = google_compute_network.narrowpath.id
}


# Asia Pacific Region, w/ RFC 1918 192.168 subnet. subnet only VPN into HQ, only port 3389. no 80 or 22
resource "google_compute_subnetwork" "narrowpath_subnet4" {
  name          = "narrowsub4"
  description   = "Taiwan"
  ip_cidr_range = "192.168.9.0/24"
  region        = "asia-east1"
  network       = google_compute_network.narrowpath.id
}


#############################################
########### Create 2 Instances ##############
#############################################












# Americas firewall rules for Americas to Allow Port 80 Traffic coke
resource "google_compute_firewall" "allow_port_80" {
  name    = "allow-port-80"
  network = google_compute_network.narrowpath.id
 
  allow {
    protocol = "tcp"
    ports    = ["80"]
   
  }
   
  source_ranges = ["172.16.1.0/24","172.16.2.0/24"]
}


# Asia Pacific firewall rules to allow port 3389, open to Asia. No 80, no 22
resource "google_compute_firewall" "allow_port_3389" {
  name    = "allow-port-3389"
  network = google_compute_network.narrowpath.id
 
  allow {
    protocol = "tcp"
    ports    = ["3389"]
   
  }
  source_ranges = ["192.168.4.0/24"]
}

resource "google_compute_firewall" "deny_port_80" {
  name    = "deny-port-80"
  network = google_compute_network.narrowpath.id

  deny {
      protocol = "tcp"
      ports    = ["80"]

    }
    source_ranges = ["0.0.0.0/24"]    
}



resource "google_compute_firewall" "deny_port_22" {
  name    = "deny-port-22"
  network = google_compute_network.narrowpath.id

  deny {
      protocol = "udp"
      ports    = ["22"]

    }
    source_ranges = ["0.0.0.0/24"]
}

#############################################
# Create VPNs, Static IP, FORWARDING RULES  #
#############################################


resource "google_compute_vpn_gateway" "narrowgate1" {
  name    = "europevpn"
  region  = "europe-north1"
  network = google_compute_network.narrowpath.id
}
# Static IP Address, check GUI, or find output command
resource "google_compute_address" "europe-static" {
  name   = "euro-static-ip"
  description = "share ip part"
  region = "europe-north1"
  address_type = "EXTERNAL"
}
 
#FORWARDING RULES FOR EUROPE (ESP, UPD 500 & UPD 4500 Rules)
 resource "google_compute_forwarding_rule" "europe_esp" {
  name        = "eu-esp"
  region      = "europe-north1"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.europe-static.address
  target      = google_compute_vpn_gateway.narrowgate1.id
}


resource "google_compute_forwarding_rule" "europe-udp500" {
  name        = "eu-udp500"
  region      = "europe-north1"
  ip_protocol = "UDP"
  ip_address  = google_compute_address.europe-static.address
  port_range  = "500"
  target      = google_compute_vpn_gateway.narrowgate1.id
}


resource "google_compute_forwarding_rule" "europe-udp4500" {
  name        = "eu-udp4500"
  region      = "europe-north1"
  ip_protocol = "UDP"
  ip_address  = google_compute_address.europe-static.address
  port_range  = "4500"
  target      = google_compute_vpn_gateway.narrowgate1.id
}


/*# target gateay resource "google_compute_vpn_gateway" "target_gateway" {
  name    = "europe-vpn-gateway"
  region = "europe-north1"
  network = google_compute_network.narrowpath.id
}*/


# VPN 2


resource "google_compute_vpn_gateway" "narrowgate2" {
  name    = "asiavpn"
  region  = "asia-east1"
  network = google_compute_network.narrowpath.id
}


########### Static IP Address, check GUI, or find output command
resource "google_compute_address" "asia-static" {
  name   = "asia-static-ip"
  description = "share ip part"
  region = "asia-east1"
}


#FORWARDING RULES FOR ASIA (ESP, UPD 500 & UPD 4500 Rules)
 resource "google_compute_forwarding_rule" "asia_esp" {
  name        = "asia-esp"
  region      = "asia-east1"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.asia-static.address
  target      = google_compute_vpn_gateway.narrowgate2.id
}


resource "google_compute_forwarding_rule" "asia-udp500" {
  name        = "asia-udp500"
  region      = "asia-east1"
  ip_protocol = "UDP"
  ip_address  = google_compute_address.asia-static.address
  port_range  = "500"
  target      = google_compute_vpn_gateway.narrowgate2.id
}


resource "google_compute_forwarding_rule" "asia-udp4500" {
  name        = "asia-udp4500"
  region      = "asia-east1"
  ip_protocol = "UDP"
  ip_address  = google_compute_address.asia-static.address
  port_range  = "4500"
  target      = google_compute_vpn_gateway.narrowgate2.id
}


######### Create Tunnels ############


resource "google_compute_vpn_tunnel" "vpntunnel1" {
  name               = "euro-to-asia-tunnel"
  region             = "europe-north1"
  target_vpn_gateway = google_compute_vpn_gateway.narrowgate1.id
  peer_ip            = google_compute_address.asia-static.address # Asia VPN Static IP
  shared_secret      = "sharedsecret"          # Replace with your shared secret .secret_data?
  ike_version        = 2


  local_traffic_selector  = ["10.33.1.0/24"]
  remote_traffic_selector = ["192.168.4.0/24"]


  depends_on = [
    google_compute_forwarding_rule.europe_esp,
    google_compute_forwarding_rule.europe-udp500,
    google_compute_forwarding_rule.europe-udp4500
  ]
}


resource "google_compute_vpn_tunnel" "vpntunnel2" {
  name               = "asia-2-euro-tunnel"
  region             = "asia-east1"
  target_vpn_gateway = google_compute_vpn_gateway.narrowgate2.id
  peer_ip            = google_compute_address.europe-static.address # Euro VPN static IP
  shared_secret      = "sharedsecret"          # Replace with your shared secret .secret_data?
  ike_version        = 2


  local_traffic_selector  = ["192.168.4.0/24"]
  remote_traffic_selector = ["10.33.1.0/24"]


  depends_on = [
    google_compute_forwarding_rule.asia_esp,
    google_compute_forwarding_rule.asia-udp500,
    google_compute_forwarding_rule.asia-udp4500
  ]
}




#######  ##########


resource "google_compute_router" "router1" {
  name        = "vpn-router1"
  description = "Europe HQ"
  region      = "europe-north1"
  network     = google_compute_network.narrowpath.id
 
}


resource "google_compute_router" "router2" {
  name        = "vpn-router2"
  region      = "asia-east1"
  description = "Asian Pacific"
  network     = google_compute_network.narrowpath.id
}


## VM Instance = Finland-Gaming-Company


resource "google_compute_instance" "europegaminghq" {
  boot_disk {
    auto_delete = true
    device_name = "europegaminghq"

    initialize_params {
      image = "projects/windows-cloud/global/images/windows-server-2022-dc-v20240516"
      size  = 150
      type  = "pd-balanced"
    }

    mode = "READ_WRITE"
  }

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false

  labels = {
    goog-ec-src = "vm_add-tf"
  }

  machine_type = "n2-standard-4"
  name         = "europegaminghq"

  network_interface {
    access_config {
      network_tier = "STANDARD"
    }

    queue_count = 0
    stack_type  = "IPV4_ONLY"
    subnetwork  = "projects/carbon-sensor-419900/regions/europe-north1/subnetworks/narrowsub1"
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  service_account {
    email  = "97471215715-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  tags = ["http-server"]
  zone = "europe-north1-a"
}


##Instance for  Asia

resource "google_compute_instance" "asia-gamingunit" {
  boot_disk {
    auto_delete = true
    device_name = "asia-gamingunit"

    initialize_params {
      image = "projects/debian-cloud/global/images/debian-12-bookworm-v20240515"
      size  = 10
      type  = "pd-balanced"
    }

    mode = "READ_WRITE"
  }

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false

  labels = {
    goog-ec-src = "vm_add-tf"
  }

  machine_type = "e2-medium"

  metadata = {
    startup-script = "#Thanks to Remo\n#!/bin/bash\n# Update and install Apache2\napt update\napt install -y apache2\n\n# Start and enable Apache2\nsystemctl start apache2\nsystemctl enable apache2\n\n# GCP Metadata server base URL and header\nMETADATA_URL=\"http://metadata.google.internal/computeMetadata/v1\"\nMETADATA_FLAVOR_HEADER=\"Metadata-Flavor: Google\"\n\n# Use curl to fetch instance metadata\nlocal_ipv4=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/network-interfaces/0/ip\")\nzone=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/zone\")\nproject_id=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/project/project-id\")\nnetwork_tags=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/tags\")\n\n# Create a simple HTML page and include instance details\ncat <<EOF > /var/www/html/index.html\n<html><body>\n<h2>THE LEAGUE OF SHADOWZ.</h2>\n<h3>Created with a direct input startup script!</h3>\n<p><b>Instance Name:</b> $(hostname -f)</p>\n<p><b>Instance Private IP Address: </b> $local_ipv4</p>\n<p><b>Zone: </b> $zone</p>\n<p><b>Project ID:</b> $project_id</p>\n<p><b>Network Tags:</b> $network_tags</p>\n</body></html>"
  }

  name = "asia-gamingunit"

  network_interface {
    access_config {
      network_tier = "PREMIUM"
    }

    queue_count = 0
    stack_type  = "IPV4_ONLY"
    subnetwork  = "projects/carbon-sensor-419900/regions/asia-east1/subnetworks/default"
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  service_account {
    email  = "97471215715-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  tags = ["http-server"]
  zone = "asia-east1-b"
}

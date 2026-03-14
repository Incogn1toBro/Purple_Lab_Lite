# Purple_Lab_Lite
An open‑source tool that lets you emulate common attacks and automatically check whether the detections fired, then produces a simple HTML report.

# Installation Instructions
1. Install Docker (ideally in VM)
2. Pull GitHub repo ```git clone https://github.com/Incogn1toBro/Purple_Lab_Lite```
3. Run ```sudo docker compose up elk-es && sudo docker compose up elk-kibana && sudo docker compose up dvwa```
4. Confirm containers are running ```sudo docker ps```
5. Navigate to Elastic Server ```http://localhost:5601```
6. Navigate to DVWA Server ```http://localhost:8080```

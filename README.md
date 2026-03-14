# Purple_Lab_Lite
An open‑source tool that lets you emulate common attacks and automatically check whether the detections fired, then produces a simple HTML report.

# Installation Instructions
1. Install Docker (ideally in VM)
2. Pull GitHub repo ```git clone https://github.com/Incogn1toBro/Purple_Lab_Lite```
3. Set owner of filebeat.yml to root ```sudo chown root filebeat.yml```
4. Remove write permissions from groups and other users ```sudo chmod go-w filebeat.yml```
5. Run ```sudo docker compose up -d```
6. Confirm containers are running ```sudo docker ps```
7. Navigate to Elastic ```http://localhost:5601```
8. Select Stack Management > Data Views > Create Data View
9. Set index pattern to  ```dvwa-raw-*```
10. Select ```Save data view to Kibana```
12. Navigate to DVWA Server ```http://localhost:8080```
13. Sign in with ```dvwa:Password1!```
14. Select ```Create/Reset Database```
15. Sign in with ```admin:password```
16. Confirm data appears in Elastic under ```Discover```

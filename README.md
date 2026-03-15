# Purple Lab Lite
An open‑source tool that lets you emulate common attacks and automatically check whether the detections fired, then produces a simple HTML report.

# Installation Instructions
1. Install Docker (ideally in VM)
2. Pull GitHub repo ```git clone https://github.com/Incogn1toBro/Purple_Lab_Lite```
3. Set owner of filebeat.yml to root ```sudo chown root ./Purple_Lab_Lite/infra/filebeat.yml```
4. Remove write permissions from groups and other users ```sudo chmod go-w ./Purple_Lab_Lite/infra/filebeat.yml```
5. Set attacker scripts to be exceutable by all ```sudo chmod +x ./Purple_Lab_Lite/infra/attack-scripts/*```
6. Run ```sudo docker compose up -d```
7. Confirm containers are running ```sudo docker ps```
8. Navigate to Elastic ```http://localhost:5601```
9. Select Stack Management > Data Views > Create Data View
10. Set index pattern to  ```dvwa-raw-*```
11. Select ```Save data view to Kibana```
12. Navigate to DVWA ```http://localhost:8080```
13. Sign in with ```dvwa:Password1!```
14. Select ```Create/Reset Database```
15. Sign in with ```admin:password```
16. Confirm data appears in Elastic under ```Discover```
17. Add DVWA IP to whichever ```attack-script``` you plan to utilise
18. Execute chosen attack-script ```sudo docker exec -it attacker /script/CHOSEN ATTACK SCRIPT.sh```

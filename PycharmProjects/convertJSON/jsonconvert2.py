import json
import pandas as pd
from json import dumps
#from flask.ext.jsonpify import jsonify
from flask import Flask, request,jsonify
from flask_restful import Resource, Api,reqparse
from sqlalchemy import create_engine
import requests
import subprocess,os
from lxml import etree
#engine = create_engine('mysql+mysqlconnector://root:1111@localhost:3306/nvd', echo=False)
#filename = "/home/hakem/Desktop/netscan.json"



app = Flask(__name__)
api = Api(app)
class graphGen(Resource):
    def readJ(self):

        scaninfo = request.get('http://127.0.0.1:7000/').json()
        data=json.loads(scaninfo)

        list = []
        for item in data["systems"]:
            for host in item["services"]:
                for CVE in host["vulnerability"]:
                    if (CVE['cve_ids']!='NOCVE'):
                        list.append(item['ip'])
                        list.append(CVE['cve_ids'])
                        list.append(host['port'])
                        list.append(host['protocol'])

        path_to_file="/home/hakem/Desktop/vulInfo.txt"

        file=open(path_to_file,"w")
        for item in list:
            file.write("%s\n" % item)
        file.close()

        print "Finished generating vulInfo.txt file"

        self.getGraph(path_to_file)

    def getGraph(self, path):
        cmd = "cd /home/hakem/Downloads/mulval && /home/hakem/Downloads/mulval/utils/nessus_translate.sh" + " " + path_to_file + " " + " && graph_gen.sh nessus.P -v -p"
        os.system(cmd)
        xml = etree.parse("/home/hakem/Downloads/mulval/AttackGraph.xml")
        return xml

api.add_resource(graphGen, '/graphGen', methods=['GET'])
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7000, debug=True)
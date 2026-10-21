import unittest
from pathlib import Path
from engine import connect,detect,ingest,normalize,parse_events,read_events
class Tests(unittest.TestCase):
 def setUp(self): self.e=parse_events(Path('samples/demo.json').read_bytes())
 def test_five_rules(self):self.assertEqual({a['rule'] for a in detect(self.e)},{'EW001','EW002','EW003','EW004','EW005'})
 def test_normal(self):self.assertEqual(detect(self.e[:5]),[])
 def test_expiration(self):
  self.e[10]['timestamp']='2026-10-19T15:00:00+00:00'
  self.assertNotIn('EW002',{a['rule'] for a in detect(self.e)})
 def test_host_isolation(self):
  self.e[10]['host']='other'
  self.assertNotIn('EW002',{a['rule'] for a in detect(self.e)})
 def test_domain_isolation(self):
  self.e[10]['domain']='other'
  self.assertNotIn('EW002',{a['rule'] for a in detect(self.e)})
 def test_missing_ip(self):
  for e in self.e:e['source_ip']=''
  self.assertNotIn('EW002',{a['rule'] for a in detect(self.e)})
 def test_other_group(self):
  self.e[12]['group_sid']='S-1-5-32-545'
  self.assertNotIn('EW004',{a['rule'] for a in detect(self.e)})
 def test_order(self):self.assertEqual(detect(self.e),detect(self.e[::-1]))
 def test_dedup(self):
  with connect(':memory:') as db:
   self.assertEqual(ingest(db,self.e),14)
   self.assertEqual(ingest(db,self.e),0)
   self.assertEqual(len(read_events(db)),14)
 def test_atomic(self):
  with connect(':memory:') as db:
   with self.assertRaises(ValueError):ingest(db,[self.e[0],{}])
   self.assertEqual(read_events(db),[])
 def test_timezone(self):
  self.e[0]['timestamp']='2026-10-19T14:00:00'
  with self.assertRaises(ValueError):normalize(self.e[0])
 def test_xml(self):
  xml=b'<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4732</EventID><TimeCreated SystemTime="2026-10-19T14:00:00Z"/><Computer>LAB</Computer></System><EventData><Data Name="TargetSid">S-1-5-32-544</Data></EventData></Event></Events>'
  self.assertEqual(detect(parse_events(xml,'xml'))[0]['rule'],'EW004')
 def test_userdata(self):
  xml=b'<Event><System><EventID>1102</EventID><TimeCreated SystemTime="2026-10-19T14:00:00Z"/><Computer>LAB</Computer></System><UserData><LogFileCleared><SubjectUserName>alex</SubjectUserName></LogFileCleared></UserData></Event>'
  self.assertEqual(parse_events(xml,'xml')[0]['user'],'alex')
 def test_entities(self):
  with self.assertRaises(ValueError):parse_events(b'<!DOCTYPE x><Events/>','xml')

import importlib.util
import pathlib
import tempfile
import unittest
import hashlib

PATH=pathlib.Path(__file__).resolve().parents[1]/"scripts"/"portal_release.py"
spec=importlib.util.spec_from_file_location("portal_release",PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ReleaseTest(unittest.TestCase):
    def test_valid_staging_manifest_and_failing_incomplete_models(self):
        with tempfile.TemporaryDirectory() as temp:
            d=pathlib.Path(temp);(d/"art").mkdir()
            (d/"index.html").write_text("<title>ShadowOps Universe</title>")
            for name in sorted(m.EXPECTED):
                data=b"glTF"+(2).to_bytes(4,"little")+b"gltf-model"*11+name.encode()
                h=hashlib.sha256(data).hexdigest()
                (d/"art"/f"{name}-{h[:12]}.glb").write_bytes(data)
            result=m.assemble(d,"a"*40)
            self.assertEqual(result["environment"],"staging")
            self.assertEqual(len(result["glb_assets"]),6)
            (d/"art"/next((d/"art").iterdir()).name).write_bytes(b"spoof")
            with self.assertRaises(ValueError):m.assemble(d,"a"*40)
    def test_mutable_release_is_forbidden(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):m.assemble(pathlib.Path(temp),"main")
if __name__=="__main__":unittest.main()

"""ShadowOps original 3D artwork: sculpted celestial vault / astronomical rose.

Run: blender --background --factory-startup --python art/blender/celestial_vault.py -- OUTPUT.glb
Only geometry/materials are authored here. Portal interaction stays in Three.js.
"""
import bpy
import math
import sys
from mathutils import Vector

bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)

def material(name, color, metallic=0.0, roughness=0.7, emissive=None):
    m = bpy.data.materials.new(name)
    m.diffuse_color = (*color, 1.0)
    m.use_nodes = True
    bsdf = m.node_tree.nodes.get("Principled BSDF")
    bsdf.inputs["Base Color"].default_value = (*color, 1.0)
    bsdf.inputs["Metallic"].default_value = metallic
    bsdf.inputs["Roughness"].default_value = roughness
    if emissive:
        socket = bsdf.inputs.get("Emission Color") or bsdf.inputs.get("Emission")
        if socket:
            socket.default_value = (*emissive, 1.0)
        strength = bsdf.inputs.get("Emission Strength")
        if strength:
            strength.default_value = 0.4
    return m

STONE = material("Blue-black aged slate", (0.043, 0.056, 0.079), .09, .83)
BRASS = material("Oxidized champagne brass", (.32, .22, .118), .78, .35)
ENAMEL = material("Moonlit enamel", (.055, .22, .28), .42, .27, (.016,.073,.10))
GROUPS = {STONE.name:[], BRASS.name:[], ENAMEL.name:[]}

def register(obj, mat):
    obj.data.materials.clear()
    obj.data.materials.append(mat)
    GROUPS[mat.name].append(obj)
    return obj

def tube(name, coords, radius, mat, closed=False, quality=5):
    shape=bpy.data.curves.new(name, type="CURVE")
    shape.dimensions="3D"
    shape.resolution_u=16
    shape.bevel_depth=radius
    shape.bevel_resolution=quality
    spline=shape.splines.new("POLY")
    spline.points.add(len(coords)-1)
    for point, xyz in zip(spline.points,coords):
        point.co = (*xyz,1)
    spline.use_cyclic_u=closed
    obj=bpy.data.objects.new(name, shape)
    bpy.context.collection.objects.link(obj)
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active=obj
    bpy.ops.object.convert(target="MESH")
    return register(bpy.context.view_layer.objects.active,mat)

def ring(name, x,y,z,major,minor,mat):
    bpy.ops.mesh.primitive_torus_add(major_segments=96, minor_segments=10,
        location=(x,y,z), major_radius=major, minor_radius=minor)
    obj=bpy.context.object
    obj.name=name
    return register(obj,mat)

def block(name, pos, dims, mat, bevel=.025):
    bpy.ops.mesh.primitive_cube_add(size=1,location=pos)
    obj=bpy.context.object
    obj.name=name
    obj.dimensions=dims
    bpy.ops.object.transform_apply(location=False,rotation=False,scale=True)
    if bevel:
        mod=obj.modifiers.new("Hand-finished edges","BEVEL")
        mod.width=bevel
        mod.segments=3
        bpy.ops.object.modifier_apply(modifier=mod.name)
        mod=obj.modifiers.new("Weighted normals","WEIGHTED_NORMAL")
        bpy.ops.object.modifier_apply(modifier=mod.name)
    return register(obj,mat)

def disk(name, pos, radius, depth, mat):
    bpy.ops.mesh.primitive_cylinder_add(vertices=96,radius=radius,depth=depth,location=pos)
    obj=bpy.context.object
    obj.name=name
    return register(obj,mat)

def star(name, x,y,z,outer,inner,rays,mat):
    verts=[]
    for i in range(rays*2):
        a = math.pi*i/rays + math.pi/2
        r=outer if i%2==0 else inner
        verts.append((x+math.cos(a)*r,y+math.sin(a)*r,z))
    # Filled triangulated fan: deterministic and with readable silhouette.
    verts.append((x,y,z))
    faces=[(rays*2,i,(i+1)%(rays*2)) for i in range(rays*2)]
    mesh=bpy.data.meshes.new(name)
    mesh.from_pydata(verts,[],faces)
    mesh.update()
    obj=bpy.data.objects.new(name,mesh)
    bpy.context.collection.objects.link(obj)
    return register(obj,mat)

# Architectural long-span barrel vault: 3D ribs set BEHIND the arch entrances.
# Top spans y 4.2..5.7, deliberately avoiding foreground click targets.
def great_arch(width,z,offset=0):
    return [(width*t/64,4.0+1.65*(max(0.0,1.0-t*t))**.72+offset,z)
            for t in range(-64,65)]
for z in [-2.85,-2.61]:
    tube("Grand barrel vault in dark stone",great_arch(6.35,z),.11,STONE,quality=5)
tube("Incised coronation rim",great_arch(6.36,-2.49,-.055),.025,BRASS)
tube("Inner deep vault reveal",great_arch(5.86,-2.72,-.18),.058,STONE)
# A small number of keyed ribs curves backwards in depth, reinforcing a 3D hall.
for x in [-5.2,-3.65,-1.85,1.85,3.65,5.2]:
    y=4.0+1.65*(1.0-(x/6.35)**2)**.72
    tube("Cross-vault carved rib",[
        (x,y-.12,-3.12),(x,y-.01,-2.92),(x,y+.05,-2.70),
        (x,y+.03,-2.49),(x,y-.035,-2.30)],.039,STONE)
    block("Decorative rib pin", (x,y-.045,-2.24),(.09,.14,.045),BRASS,.014)
# Repeated high slate coffers with inset brass piping, behind celestial oculus.
for x in [-4.6,-3.15,-1.65,1.65,3.15,4.6]:
    y=4.08+1.30*(1-(x/6.35)**2)**.72
    # Small incised stone rosettes avoid blocky plaques or visible low-poly kitbash.
    star("Vault carved celestial rosette",x,y-.20,-2.18,.108,.044,8,BRASS)
    disk("Rosette inset enamel",(x,y-.20,-2.146),.023,.013,ENAMEL)

# Central astronomical rose/oculus. The elements are layered physically in Z.
disk("Deep lapis moon dial",(0,4.87,-2.30),.73,.10,STONE)
disk("Cerulean celestial medallion",(0,4.87,-2.215),.60,.05,ENAMEL)
ring("Wide architectural bezel",0,4.87,-2.115,.716,.058,BRASS)
ring("Engraved inner bezel",0,4.87,-2.068,.548,.013,BRASS)
ring("Circular orbit line",0,4.87,-2.027,.34,.010,BRASS)
star("Eight-point astronomer's star",0,4.87,-1.995,.284,.096,8,BRASS)
disk("Central moon heart",(0,4.87,-1.963),.068,.044,ENAMEL)
for i in range(24):
    angle=2*math.pi*i/24
    radius=.625
    cx=radius*math.cos(angle); cy=4.87+radius*math.sin(angle)
    length=.092 if i%6==0 else .052
    # Cylindrical pins, tilted around their Z-axis.
    pin=block("Astronomical graduation",(cx,cy,-2.036),(.016,length,.029),BRASS,.004)
    pin.rotation_euler[2]=angle-math.pi/2
for angle in [math.pi*.25,math.pi*.75,math.pi*1.25,math.pi*1.75]:
    x=.41*math.cos(angle);y=4.87+.41*math.sin(angle)
    disk("Enamel cardinal cabochon",(x,y,-2.008),.041,.026,ENAMEL)

# Two dramatic sculpted corner brackets echo the copper observatory instruments.
for sign in [-1,1]:
    x=sign*5.72
    tube("Vault wall bracket",[(x,3.55,-2.63),(x,3.92,-2.57),
          (x-sign*.23,4.28,-2.47),(x-sign*.50,4.45,-2.39)],.075,STONE)
    ring("Sconce retainer",x-sign*.52,4.46,-2.35,.13,.023,BRASS)
    star("Sconce enamel seal",x-sign*.52,4.46,-2.305,.065,.025,6,ENAMEL)


# Forecourt: inset, honed-stone approach to all three destinations.
# This completes the architectural composition without bright UI-like strips.
# These are truly shaped DCC meshes, merged into the existing THREE PBR groups.
# All coordinates are deliberately Y-up; GLB export_yup=False preserves them.
def floor_ring(name, cx, cz, y, radius, gauge, mat):
    obj=ring(name,cx,y,cz,radius,gauge,mat)
    obj.rotation_euler[0]=math.pi/2
    return obj

def floor_rose(name, cx, cz, y, outer, inner, points, mat):
    verts=[]
    for i in range(points*2):
        a=math.pi*i/points+math.pi/2
        radius=outer if i%2==0 else inner
        verts.append((cx+math.cos(a)*radius,y,cz+math.sin(a)*radius))
    verts.append((cx,y,cz))
    faces=[(points*2,(i+1)%(points*2),i) for i in range(points*2)]
    mesh=bpy.data.meshes.new(name)
    mesh.from_pydata(verts,[],faces)
    mesh.update()
    obj=bpy.data.objects.new(name,mesh)
    bpy.context.collection.objects.link(obj)
    return register(obj,mat)

# A few nearly flush stone inlays with simple faces. Do not subdivide
# invisible edge bevels: the authored brass seams carry the detail.
# Their upper face is at -0.103, just above the existing metal dais (-0.152).
for passage_x in [-3.22,0,3.22]:
    for i in range(6):
        z=-.77+i*.52
        staggering=(.035 if (i+round(passage_x))%2==0 else -.035)
        block("Honed basalt passage stone",
              (passage_x+staggering,-.127,z),
              (1.14+.055*i,.046,.425),STONE,0)
        # Two hairline brass seams frame each approach as floor marquetry.
    for side in [-1,1]:
        tube("Warm brass perspective floor inlay",
             [(passage_x+side*(.59+.025*i),-.092,-.99+i*.52)
              for i in range(7)],.007,BRASS,quality=3)

# One inset, centered compass rose: a restrained celestial instrument that
# ties the three worlds together, visible in the foreground from the camera.
cx,cz=0,3.00
floor_ring("Forecourt circle, engraved brass",cx,cz,-.065,.79,.013,BRASS)
floor_ring("Inner compass graduation",cx,cz,-.060,.62,.009,BRASS)
floor_rose("Eight-point navigational mosaic",cx,cz,-.054,.50,.19,8,BRASS)
floor_rose("Lapis compass core",cx,cz,-.045,.17,.070,8,ENAMEL)
for i in range(16):
    theta=2*math.pi*i/16
    rx=cx+math.cos(theta)*.715
    rz=cz+math.sin(theta)*.715
    marker=block("Inset brass cardinal graduation",
                 (rx,-.049,rz),
                 (.018,.009,.082 if i%4==0 else .045),BRASS,0)
    marker.rotation_euler[1]=-theta+math.pi/2

# Collapse dozens of individually shaped DCC objects into exactly three meshes
# (one per PBR material) for a deliberately bounded GPU draw-call footprint.
for mat_name,objects in GROUPS.items():
    bpy.ops.object.select_all(action="DESELECT")
    for obj in objects: obj.select_set(True)
    bpy.context.view_layer.objects.active=objects[0]
    bpy.ops.object.join()
    bpy.context.object.name="ShadowOps celestial vault / "+mat_name

result_path=sys.argv[sys.argv.index("--")+1] if "--" in sys.argv else None
if not result_path:
    raise ValueError("Required output.glb path after --")
bpy.ops.export_scene.gltf(filepath=result_path,export_format="GLB",
                          export_apply=True,export_yup=False,
                          use_selection=False,export_texcoords=False,
                          export_normals=True,export_materials="EXPORT")
print("SHADOWOPS_VAULT_OUTPUT="+result_path)

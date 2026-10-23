"""Atlas Chamber: original chess knight sculpture, not an off-the-shelf model.

Run: blender --background --factory-startup --python art/blender/atlas_knight.py -- OUT.glb
Y is vertical in the exported asset (export_yup=False), matching the Atlas
Chamber table's real geometry. No textures or external model dependencies.
"""
import bpy
import bmesh
import math
import sys

bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)

def material(name, rgb, metal, rough):
    m = bpy.data.materials.new(name)
    m.diffuse_color = (*rgb, 1)
    m.use_nodes = True
    p = m.node_tree.nodes.get("Principled BSDF")
    p.inputs["Base Color"].default_value = (*rgb, 1)
    p.inputs["Metallic"].default_value = metal
    p.inputs["Roughness"].default_value = rough
    return m

IVORY = material("Moonstone, polished bone", (.65, .67, .64), .10, .38)
GOLD = material("Chiselled antique gold", (.39, .245, .10), .76, .29)
INK = material("Obsidian inset", (.020, .032, .048), .24, .25)
GROUPS = {m.name: [] for m in (IVORY, GOLD, INK)}

def register(obj, mat):
    # A joined mesh inherits the active object's local axes; if its original
    # primitive was an X-rotated cylinder, accessor bounds may incorrectly
    # report the horse height along Z. Bake every source mesh into shared
    # world-space/Y-up coordinates before batching by PBR material.
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active=obj
    bpy.ops.object.transform_apply(location=True,rotation=True,scale=True)
    obj.data.materials.clear()
    obj.data.materials.append(mat)
    GROUPS[mat.name].append(obj)
    return obj

def cylinder(name, radius, height, y, mat, vertices=48):
    bpy.ops.mesh.primitive_cylinder_add(vertices=vertices, radius=radius,
        depth=height, location=(0,y,0), rotation=(math.pi/2,0,0))
    obj=bpy.context.object
    obj.name=name
    return register(obj,mat)

def torus(name, radius, tube, y, mat):
    bpy.ops.mesh.primitive_torus_add(major_segments=48, minor_segments=8,
        major_radius=radius, minor_radius=tube, location=(0,y,0),
        rotation=(math.pi/2,0,0))
    ob=bpy.context.object
    ob.name=name
    return register(ob,mat)

def outline(name, points, depth, bevel, mat, z=0):
    """Smooth, thick real relief from an original Bezier contour in XY."""
    curve=bpy.data.curves.new(name,type="CURVE")
    curve.dimensions="2D"
    curve.resolution_u=8
    curve.fill_mode="BOTH"
    curve.extrude=depth
    curve.bevel_depth=bevel
    curve.bevel_resolution=2
    spline=curve.splines.new("BEZIER")
    spline.bezier_points.add(len(points)-1)
    for p,(x,y) in zip(spline.bezier_points,points):
        p.co=(x,y,0)
        p.handle_left_type="AUTO"
        p.handle_right_type="AUTO"
    spline.use_cyclic_u=True
    ob=bpy.data.objects.new(name,curve)
    bpy.context.collection.objects.link(ob)
    ob.location.z=z
    bpy.ops.object.select_all(action="DESELECT")
    ob.select_set(True)
    bpy.context.view_layer.objects.active=ob
    bpy.ops.object.convert(target="MESH")
    return register(bpy.context.object,mat)

def engraving(name, coords, gauge, mat):
    curve=bpy.data.curves.new(name,type="CURVE")
    curve.dimensions="3D"
    # Screen-space ornaments do not need Blender's default 12 Bezier subdivisions.
    curve.resolution_u=7
    curve.bevel_depth=gauge
    curve.bevel_resolution=2
    spline=curve.splines.new("BEZIER")
    spline.bezier_points.add(len(coords)-1)
    for point,xyz in zip(spline.bezier_points,coords):
        point.co=xyz
        point.handle_left_type="AUTO"
        point.handle_right_type="AUTO"
    ob=bpy.data.objects.new(name,curve)
    bpy.context.collection.objects.link(ob)
    bpy.ops.object.select_all(action="DESELECT")
    ob.select_set(True)
    bpy.context.view_layer.objects.active=ob
    bpy.ops.object.convert(target="MESH")
    return register(bpy.context.object,mat)

def bead(name,loc,scale,mat):
    bpy.ops.mesh.primitive_uv_sphere_add(segments=12,ring_count=8,
        location=loc)
    ob=bpy.context.object
    ob.name=name
    ob.scale=scale
    bpy.ops.object.transform_apply(location=False,rotation=False,scale=True)
    return register(ob,mat)

# Actual turned pedestal rather than a hovering flat horse outline.
cylinder("Ebon foot",.283,.078,.052,INK)
cylinder("Bone shoulder",.260,.065,.109,IVORY)
torus("Engraved foot ferrule",.273,.016,.077,GOLD)
torus("Small gilt shoulder",.245,.010,.141,GOLD)

# One-piece original carved horse neck and muzzle, fully bevelled in depth.
# Side profile faces to the right. The head is tall enough to read on a
# 390px camera, while the pedestal still fits one chessboard square.
outline("Carved swept neck and horse head",[
    (-.205,.141),(.205,.141),(.104,.280),(.091,.416),
    (.204,.495),(.296,.595),(.296,.657),(.251,.697),
    (.144,.693),(.075,.788),(.016,.985),(-.074,1.088),
    (-.144,1.050),(-.193,.913),(-.238,.773),
    (-.276,.603),(-.228,.460),(-.180,.331)
],.120,.035,IVORY)

# Split tapering ears are separate sculptural planes, not a pyramid bolted on.
outline("Near horse ear",[
    (-.095,.995),(-.112,1.272),(.010,1.125),(.012,1.010)
],.052,.018,IVORY,z=.087)
outline("Far horse ear",[
    (-.040,1.020),(.031,1.210),(.093,1.063),(.050,.984)
],.033,.014,IVORY,z=-.105)

# Incised fluting follows the flowing mane and cheek musculature. The
# stepped gilding is actual world-space relief, not a baked cartoon stripe.
for side in [-1,1]:
    z=side*.162
    engraving("Mane incision A",[
      (-.193,.870,z),(-.161,.765,z),(-.219,.668,z),
      (-.196,.550,z),(-.146,.475,z)],.009,GOLD)
    engraving("Mane incision B",[
      (-.155,.856,z),(-.123,.733,z),(-.159,.647,z),
      (-.126,.564,z)],.006,GOLD)
    engraving("Gilded cheek harness",[
      (.098,.758,z),(.087,.655,z),(.176,.550,z),
      (.235,.582,z)],.012,GOLD)
    engraving("Carved neck channel",[
      (-.090,.433,z),(-.022,.352,z),(.015,.252,z)],.008,GOLD)
    bead("Inset polished eye",(.113,.780,side*.163),
      (.034,.035,.012),INK)
    bead("Small bronze eye bezel",(.113,.780,side*.158),
      (.047,.047,.009),GOLD)
    bead("Eye dark centre",(.113,.780,side*.176),
      (.026,.026,.010),INK)
    bead("Muzzle nostril",(.261,.638,side*.139),
      (.024,.017,.010),INK)
    bead("Horse bit pin",(.167,.545,side*.161),
      (.021,.021,.013),GOLD)

# Raised horsehair braid over the back of the neck, with restrained insets.
for i in range(6):
    y=.42+i*.095
    x=-.183-.045*math.sin(i*.52)
    bead("Braided mane stud",(x,y,.175),(.032,.045,.018),GOLD)

# Bound tessellation for the 390px hero: preserve the Bezier profile and
# three PBR batches without shipping subpixel curved surfaces as extra vertices.
# Preserve just three batchable PBR primitives. The glTF runtime only
# instantiates three meshes and is never authoritative for interaction.
for name,objects in GROUPS.items():
    bpy.ops.object.select_all(action="DESELECT")
    for ob in objects: ob.select_set(True)
    bpy.context.view_layer.objects.active=objects[0]
    bpy.ops.object.join()
    # The active pedestal mesh was rotated +90° on X. Joining keeps that
    # rotation as the GLB node transform, so POSITION accessors appear Z-up.
    # Bake world transforms once: browser geometry and Y-up bounds now agree.
    bpy.ops.object.transform_apply(location=True, rotation=True, scale=True)
    # Blender glTF auto-triangulation can flip equal-cost ngon diagonals between
    # identical builds. Fix the triangulation explicitly before hashing the GLB.
    bm=bmesh.new()
    bm.from_mesh(bpy.context.object.data)
    bmesh.ops.triangulate(bm,faces=list(bm.faces),quad_method="FIXED",ngon_method="EAR_CLIP")
    bm.to_mesh(bpy.context.object.data)
    bm.free()
    bpy.context.object.name="Atlas Knight / "+name

filename=sys.argv[sys.argv.index("--")+1] if "--" in sys.argv else None
if not filename:
    raise ValueError("Expected output GLB path after --")
bpy.ops.export_scene.gltf(filepath=filename,export_format="GLB",
    export_apply=True,export_yup=False,use_selection=False,
    export_materials="EXPORT",export_normals=True,export_texcoords=False)
print("ATLAS_KNIGHT_GLB="+filename)

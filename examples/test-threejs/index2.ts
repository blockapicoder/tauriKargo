import * as THREE from 'three';
import {OrbitControls} from 'three/examples/jsm/controls/OrbitControls.js';

// ———————————————————————————————————————————————
// Rendu
// ———————————————————————————————————————————————
const renderer = new THREE.WebGLRenderer({antialias: true});
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.1;
// Color management moderne (Three r152+)
renderer.outputColorSpace = THREE.SRGBColorSpace;

document.getElementById('app')!.appendChild(renderer.domElement);

// ———————————————————————————————————————————————
// Scène & Caméra
// ———————————————————————————————————————————————
const scene = new THREE.Scene();
scene.background = new THREE.Color('#0e0f14');

const camera = new THREE.PerspectiveCamera(
    60, window.innerWidth / window.innerHeight, 0.1, 100
);
camera.position.set(3.5, 2.2, 6);

// Contrôles caméra
const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;
controls.target.set(0, 0.75, 0);


// ———————————————————————————————————————————————
// Lumières
// ———————————————————————————————————————————————
// Lumière ambiante douce
const ambient = new THREE.AmbientLight(0xffffff, 0.25);
scene.add(ambient);

// Directionnelle (avec ombres)
const dirLight = new THREE.DirectionalLight(0xffffff, 1.0);
dirLight.position.set(5, 6, 4);
dirLight.castShadow = true;
dirLight.shadow.mapSize.set(1024, 1024);
dirLight.shadow.camera.near = 0.5;
dirLight.shadow.camera.far = 20;
dirLight.shadow.normalBias = 0.02;
scene.add(dirLight);

// Point light colorée animée, pour des reflets sympas
const pointLight = new THREE.PointLight(0x66ccff, 1.0, 20, 2);
pointLight.position.set(-2, 2, -2);
scene.add(pointLight);

// Petite sphère pour visualiser la point light
const plHelper = new THREE.Mesh(
    new THREE.SphereGeometry(0.05, 12, 12),
    new THREE.MeshBasicMaterial({color: 0x66ccff})
);
pointLight.add(plHelper);

// ———————————————————————————————————————————————
// Sol qui reçoit les ombres
// ———————————————————————————————————————————————
const ground = new THREE.Mesh(
    new THREE.PlaneGeometry(30, 30),
    new THREE.ShadowMaterial({opacity: 0.35})
);
ground.rotation.x = -Math.PI / 2;
ground.position.y = 0;
ground.receiveShadow = true;
scene.add(ground);

// ———————————————————————————————————————————————
// Objets : Cube + Sphère
// ———————————————————————————————————————————————
const matMetal: THREE.MeshStandardMaterialParameters = {
    roughness: 0.35,
    metalness: 0.4,
    color: new THREE.Color('#ff7f50'), // corail
};
const matGloss: THREE.MeshStandardMaterialParameters = {
    roughness: 0.15,
    metalness: 0.1,
    color: new THREE.Color('#7aa2ff'), // bleu clair
};

const cube = new THREE.Mesh(
    new THREE.BoxGeometry(1, 1, 1),
    new THREE.MeshStandardMaterial(matMetal)
);
cube.position.set(-1.5, 0.5, 0);
cube.castShadow = true;
cube.receiveShadow = false;
scene.add(cube);

const sphere = new THREE.Mesh(
    new THREE.SphereGeometry(0.7, 48, 48),
    new THREE.MeshStandardMaterial(matGloss)
);
sphere.position.set(1.5, 0.7, 0);
sphere.castShadow = true;
scene.add(sphere);

// ———————————————————————————————————————————————
// Helpers (optionnels)
// ———————————————————————————————————————————————
// const dlHelper = new THREE.DirectionalLightHelper(dirLight, 0.5);
// scene.add(dlHelper);
// scene.add(new THREE.AxesHelper(2));

// ———————————————————————————————————————————————
/** Animation */
// ———————————————————————————————————————————————
const clock = new THREE.Clock();

function animate() {
    const t = clock.getElapsedTime();

    // Rotation des objets
    cube.rotation.x = t * 0.8;
    cube.rotation.y = t * 1.2;

    sphere.rotation.y = -t * 0.6;
    sphere.rotation.z = Math.sin(t * 0.5) * 0.15;

    // Animation douce de la point light
    pointLight.position.x = Math.cos(t * 0.8) * 2.2;
    pointLight.position.z = Math.sin(t * 0.8) * 2.2;
    pointLight.position.y = 1.8 + Math.sin(t * 1.6) * 0.3;

    controls.update();
    renderer.render(scene, camera);
    requestAnimationFrame(animate);
}

animate();

// ———————————————————————————————————————————————
/** Resize */
// ———————————————————————————————————————————————
window.addEventListener('resize', () => {
    const {innerWidth: w, innerHeight: h} = window;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
});

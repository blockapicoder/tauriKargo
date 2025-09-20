// TypeScript minimal pour charger le modèle glTF dans three.js
// - Utilisez un bundler (Vite, Webpack) ou un projet Next.js. 
// - Installez: npm i three

import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';

// Création scène/caméra/rendu
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


const scene = new THREE.Scene();
scene.background = new THREE.Color(0xf3f5f7);

const camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 100);
camera.position.set(4.2, 2.2, 4.8);

const controls = new OrbitControls(camera, renderer.domElement);
controls.target.set(0, 0.7, 0);
controls.enableDamping = true;

// Lumière douce + ombres
const hemi = new THREE.HemisphereLight(0xffffff, 0xb8c1cc, 0.7);
scene.add(hemi);

const dir = new THREE.DirectionalLight(0xffffff, 1.2);
dir.position.set(5, 6, 3);
dir.castShadow = true;
dir.shadow.mapSize.set(2048, 2048);
dir.shadow.normalBias = 0.015;
scene.add(dir);

// Sol simple
const groundMat = new THREE.MeshStandardMaterial({ color: 0xe6eaee, roughness: 0.9, metalness: 0.0 });
const ground = new THREE.Mesh(new THREE.CircleGeometry(20, 64), groundMat);
ground.rotation.x = -Math.PI / 2;
ground.receiveShadow = true;
scene.add(ground);

// Charger le modèle (placez le fichier voiture_lowpoly.gltf dans votre dossier public/assets)
const loader = new GLTFLoader();
loader.load('/voiture_lowpoly.gltf', (gltf) => {
  const car = gltf.scene;
  car.traverse((obj) => {
    if ((obj as THREE.Mesh).isMesh) {
      const m = obj as THREE.Mesh;
      m.castShadow = true;
      m.receiveShadow = true;
    }
  });
  scene.add(car);
}, (progress) => {
  // Optionnel: console.log(`Loading ${(progress.loaded / progress.total) * 100}%`);
}, (err) => {
  console.error('Échec de chargement du modèle', err);
});

// Réactivité
window.addEventListener('resize', () => {
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
});

// Boucle d'animation
function tick() {
  controls.update();
  renderer.render(scene, camera);
  requestAnimationFrame(tick);
}
tick();

// Si vous n'avez pas d'élément <canvas id="app" />, le renderer crée un canvas automatiquement.
// Ajoutez dans votre HTML : <canvas id="app"></canvas> ou montez renderer.domElement manuellement.

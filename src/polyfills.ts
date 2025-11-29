// src/polyfills.ts
import { Buffer } from 'buffer';
import process from 'process';

if (!(window as any).Buffer)  (window as any).Buffer  = Buffer;
if (!(window as any).process) (window as any).process = process;
if (!(window as any).global)  (window as any).global  = window; // some libs test for global

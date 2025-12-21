import React, { useState, useRef } from 'react';
import {
  Upload,
  FileText,
  X,
  AlertTriangle,
  CheckCircle,
  Loader2,
  HardDrive,
  FileArchive,
  Info,
} from 'lucide-react';

/**
 * ImageUploader - Upload Docker images or Dockerfiles for scanning
 * Supports:
 * - Docker image tarballs (.tar, .tar.gz)
 * - Dockerfiles (to build and scan)
 */

const ImageUploader = ({ onUploadComplete, onClose }) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [uploadType, setUploadType] = useState('tarball'); // 'tarball' or 'dockerfile'
  const fileInputRef = useRef(null);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (file) => {
    setError(null);
    
    // Validate file type
    const validExtensions = uploadType === 'tarball' 
      ? ['.tar', '.tar.gz', '.tgz']
      : ['Dockerfile', '.dockerfile'];
    
    const fileName = file.name.toLowerCase();
    const isValid = uploadType === 'tarball'
      ? validExtensions.some(ext => fileName.endsWith(ext))
      : fileName === 'dockerfile' || fileName.endsWith('.dockerfile');

    if (!isValid) {
      setError(`Invalid file type. Expected ${uploadType === 'tarball' ? 'tar/tar.gz' : 'Dockerfile'}`);
      return;
    }

    // Check file size (max 2GB for tarballs, 1MB for Dockerfiles)
    const maxSize = uploadType === 'tarball' ? 2 * 1024 * 1024 * 1024 : 1 * 1024 * 1024;
    if (file.size > maxSize) {
      setError(`File too large. Maximum size: ${uploadType === 'tarball' ? '2GB' : '1MB'}`);
      return;
    }

    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setUploadProgress(0);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('type', uploadType);

      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const progress = Math.round((e.loaded / e.total) * 100);
          setUploadProgress(progress);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          const response = JSON.parse(xhr.responseText);
          onUploadComplete?.(response);
          setSelectedFile(null);
          setUploadProgress(0);
        } else {
          let errorMsg = 'Upload failed';
          try {
            const errResponse = JSON.parse(xhr.responseText);
            errorMsg = errResponse.detail || errResponse.error?.message || errorMsg;
          } catch {}
          setError(errorMsg);
        }
        setUploading(false);
      });

      xhr.addEventListener('error', () => {
        setError('Network error. Please try again.');
        setUploading(false);
      });

      xhr.open('POST', `${API_URL}/api/v1/scan/upload`);
      xhr.send(formData);

    } catch (err) {
      setError(err.message || 'Upload failed');
      setUploading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-cyber-dark border border-cyber-gray rounded-xl w-full max-w-lg overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-gray">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-neon-blue/20 rounded-lg">
              <Upload className="w-5 h-5 text-neon-blue" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Upload Image</h2>
              <p className="text-xs text-slate-500">Scan a local Docker image</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Upload type selector */}
        <div className="flex border-b border-cyber-gray">
          <button
            onClick={() => {
              setUploadType('tarball');
              setSelectedFile(null);
              setError(null);
            }}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
              uploadType === 'tarball'
                ? 'text-neon-blue border-b-2 border-neon-blue bg-neon-blue/5'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <FileArchive className="w-4 h-4" />
            Image Tarball
          </button>
          <button
            onClick={() => {
              setUploadType('dockerfile');
              setSelectedFile(null);
              setError(null);
            }}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
              uploadType === 'dockerfile'
                ? 'text-neon-blue border-b-2 border-neon-blue bg-neon-blue/5'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <FileText className="w-4 h-4" />
            Dockerfile
          </button>
        </div>

        {/* Content */}
        <div className="p-4">
          {/* Info box */}
          <div className="flex items-start gap-3 p-3 mb-4 bg-neon-blue/5 border border-neon-blue/20 rounded-lg">
            <Info className="w-4 h-4 text-neon-blue mt-0.5 flex-shrink-0" />
            <div className="text-xs text-slate-300">
              {uploadType === 'tarball' ? (
                <>
                  <p className="font-medium text-white mb-1">Export your Docker image:</p>
                  <code className="block p-2 bg-cyber-black rounded font-mono text-neon-cyan">
                    docker save myimage:tag -o myimage.tar
                  </code>
                </>
              ) : (
                <>
                  <p className="font-medium text-white mb-1">Upload a Dockerfile to build and scan:</p>
                  <p>The image will be built in an isolated environment and scanned for vulnerabilities.</p>
                </>
              )}
            </div>
          </div>

          {/* Drop zone */}
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`
              relative border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all
              ${dragActive 
                ? 'border-neon-blue bg-neon-blue/10' 
                : 'border-cyber-gray hover:border-slate-500 hover:bg-cyber-gray/30'
              }
              ${selectedFile ? 'border-neon-green bg-neon-green/5' : ''}
            `}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              accept={uploadType === 'tarball' ? '.tar,.tar.gz,.tgz' : '.dockerfile,Dockerfile'}
              className="hidden"
            />

            {selectedFile ? (
              <div className="flex flex-col items-center">
                <CheckCircle className="w-10 h-10 text-neon-green mb-3" />
                <p className="text-sm font-medium text-white mb-1">{selectedFile.name}</p>
                <p className="text-xs text-slate-500">{formatFileSize(selectedFile.size)}</p>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedFile(null);
                  }}
                  className="mt-3 text-xs text-slate-400 hover:text-white"
                >
                  Choose different file
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center">
                {uploadType === 'tarball' ? (
                  <HardDrive className="w-10 h-10 text-slate-500 mb-3" />
                ) : (
                  <FileText className="w-10 h-10 text-slate-500 mb-3" />
                )}
                <p className="text-sm text-slate-300 mb-1">
                  Drag and drop or <span className="text-neon-blue">browse</span>
                </p>
                <p className="text-xs text-slate-500">
                  {uploadType === 'tarball' 
                    ? 'Supports .tar, .tar.gz (max 2GB)'
                    : 'Dockerfile or .dockerfile (max 1MB)'
                  }
                </p>
              </div>
            )}
          </div>

          {/* Error message */}
          {error && (
            <div className="flex items-center gap-2 mt-4 p-3 bg-severity-critical/10 border border-severity-critical/30 rounded-lg">
              <AlertTriangle className="w-4 h-4 text-severity-critical flex-shrink-0" />
              <p className="text-sm text-severity-critical">{error}</p>
            </div>
          )}

          {/* Progress bar */}
          {uploading && (
            <div className="mt-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Uploading...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="h-2 bg-cyber-gray rounded-full overflow-hidden">
                <div 
                  className="h-full bg-neon-blue transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-4 border-t border-cyber-gray">
          <button
            onClick={onClose}
            disabled={uploading}
            className="px-4 py-2 text-sm text-slate-400 hover:text-white hover:bg-cyber-gray rounded-lg transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-neon-blue hover:bg-neon-blue/80 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Uploading...
              </>
            ) : (
              <>
                <Upload className="w-4 h-4" />
                Upload & Scan
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ImageUploader;

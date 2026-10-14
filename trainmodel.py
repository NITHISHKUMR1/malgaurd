import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

class MalwareDetectionModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_columns = None
        self.history = None
        
    def load_and_preprocess_data(self, csv_path):
        """Load and preprocess the malware dataset"""
        print("Loading dataset...")
        df = pd.read_csv(csv_path)
        
        # Separate features and target
        if 'malware_family' in df.columns:
            # Multi-class classification (malware type)
            self.is_multiclass = True
            y = df['malware_family']
            X = df.drop(columns=['malware_family', 'file_id', 'file_name', 'detection_date', 'severity'], 
                       errors='ignore')
        else:
            # Binary classification
            self.is_multiclass = False
            y = df['malware'] if 'malware' in df.columns else df['detection_score'] > 0.5
            X = df.drop(columns=['malware', 'detection_score', 'file_id', 'file_name', 'detection_date'], 
                       errors='ignore')
        
        # Handle categorical features
        categorical_columns = X.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            self.label_encoders[col] = le
        
        self.feature_columns = X.columns.tolist()
        
        # Encode target
        self.target_encoder = LabelEncoder()
        y_encoded = self.target_encoder.fit_transform(y)
        self.num_classes = len(self.target_encoder.classes_)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test, X_train, X_test
    
    def build_model(self, input_dim):
        """Build ANN model"""
        if self.is_multiclass:
            # Multi-class classification
            model = keras.Sequential([
                layers.Input(shape=(input_dim,)),
                layers.Dense(256, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.4),
                layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(64, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.2),
                layers.Dense(self.num_classes, activation='softmax')
            ])
            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
        else:
            # Binary classification
            model = keras.Sequential([
                layers.Input(shape=(input_dim,)),
                layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(32, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.2),
                layers.Dense(1, activation='sigmoid')
            ])
            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy', keras.metrics.AUC(name='auc')]
            )
        
        return model
    
    def train(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=32):
        """Train the model"""
        input_dim = X_train.shape[1]
        self.model = self.build_model(input_dim)
        
        # Callbacks
        early_stopping = EarlyStopping(
            monitor='val_loss',
            patience=15,
            restore_best_weights=True,
            verbose=1
        )
        
        reduce_lr = ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=8,
            min_lr=0.00001,
            verbose=1
        )
        
        print("\nTraining model...")
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping, reduce_lr],
            verbose=1
        )
        
        return self.history
    
    def evaluate(self, X_test, y_test):
        """Evaluate the model"""
        print("\nEvaluating model...")
        
        if self.is_multiclass:
            y_pred_probs = self.model.predict(X_test)
            y_pred = np.argmax(y_pred_probs, axis=1)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, target_names=self.target_encoder.classes_)
            cm = confusion_matrix(y_test, y_pred)
            auc_score = None
        else:
            y_pred_probs = self.model.predict(X_test)
            y_pred = (y_pred_probs > 0.5).astype(int)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, target_names=['Benign', 'Malware'])
            cm = confusion_matrix(y_test, y_pred)
            auc_score = roc_auc_score(y_test, y_pred_probs)
        
        return accuracy, report, cm, auc_score, y_pred_probs
    
    def plot_training_history(self, save_path='static/images/training_history.png'):
        """Plot training history"""
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        
        # Plot accuracy
        axes[0].plot(self.history.history['accuracy'], label='Training Accuracy')
        axes[0].plot(self.history.history['val_accuracy'], label='Validation Accuracy')
        axes[0].set_title('Model Accuracy')
        axes[0].set_xlabel('Epoch')
        axes[0].set_ylabel('Accuracy')
        axes[0].legend()
        axes[0].grid(True)
        
        # Plot loss
        axes[1].plot(self.history.history['loss'], label='Training Loss')
        axes[1].plot(self.history.history['val_loss'], label='Validation Loss')
        axes[1].set_title('Model Loss')
        axes[1].set_xlabel('Epoch')
        axes[1].set_ylabel('Loss')
        axes[1].legend()
        axes[1].grid(True)
        
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        
        return save_path
    
    def plot_confusion_matrix(self, cm, save_path='static/images/confusion_matrix.png'):
        """Plot confusion matrix"""
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=self.target_encoder.classes_ if self.is_multiclass else ['Benign', 'Malware'],
                    yticklabels=self.target_encoder.classes_ if self.is_multiclass else ['Benign', 'Malware'])
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        
        return save_path
    
    def save_model(self, model_path='models/malware_model.h5', scaler_path='models/scaler.pkl'):
        """Save model and preprocessing objects"""
        os.makedirs('models', exist_ok=True)
        
        self.model.save(model_path)
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.label_encoders, 'models/label_encoders.pkl')
        joblib.dump(self.target_encoder, 'models/target_encoder.pkl')
        joblib.dump(self.feature_columns, 'models/feature_columns.pkl')
        joblib.dump(self.is_multiclass, 'models/is_multiclass.pkl')
        
        print(f"Model saved to {model_path}")
        print(f"Scaler saved to {scaler_path}")

# Training function
def train_malware_model(csv_path='malware_dataset_multitype.csv'):
    """Main training function"""
    # Create model instance
    detector = MalwareDetectionModel()
    
    # Load and preprocess data
    X_train_scaled, X_test_scaled, y_train, y_test, X_train_raw, X_test_raw = detector.load_and_preprocess_data(csv_path)
    
    # Split validation set
    X_train_final, X_val, y_train_final, y_val = train_test_split(
        X_train_scaled, y_train, test_size=0.2, random_state=42
    )
    
    # Train model
    history = detector.train(X_train_final, y_train_final, X_val, y_val, epochs=100)
    
    # Evaluate
    accuracy, report, cm, auc_score, predictions = detector.evaluate(X_test_scaled, y_test)
    
    print(f"\n{'='*60}")
    print("TRAINING COMPLETE!")
    print(f"{'='*60}")
    print(f"Accuracy: {accuracy:.4f}")
    if auc_score:
        print(f"AUC Score: {auc_score:.4f}")
    print(f"\nClassification Report:\n{report}")
    
    # Plot results
    detector.plot_training_history()
    detector.plot_confusion_matrix(cm)
    
    # Save model
    detector.save_model()
    
    return detector, accuracy, report, cm, auc_score

if __name__ == "__main__":
    train_malware_model()
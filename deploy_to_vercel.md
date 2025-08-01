# Deploy Updated Backend to Vercel

## 🚀 Quick Deployment Steps

### 1. Commit and Push Changes

```bash
git add .
git commit -m "Fix MongoDB configuration for Vercel deployment"
git push origin main
```

### 2. Set Environment Variables in Vercel

1. Go to your Vercel dashboard
2. Select your CyberRazor backend project
3. Go to **Settings** → **Environment Variables**
4. Add/Update these variables:

```
MONGODB_URL=mongodb+srv://your_username:your_password@your_cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB_NAME=cyberrazor
```

### 3. Verify Deployment

After deployment, test these endpoints:

```bash
# Health check
curl https://cyberrazor-backend.vercel.app/api/health

# Debug info (new endpoint)
curl https://cyberrazor-backend.vercel.app/api/debug

# Root endpoint
curl https://cyberrazor-backend.vercel.app/
```

## 🔧 What's Fixed

The updated backend includes:

1. **Removed hardcoded MongoDB URL** - Now properly uses environment variables
2. **Better error messages** - More informative debugging information
3. **Improved connection handling** - Better retry logic and error reporting
4. **New debug endpoint** - `/api/debug` for troubleshooting
5. **Enhanced health endpoint** - Includes error messages in response

## 📋 Expected Results

After successful deployment:

- Health endpoint should show: `"status": "operational"`
- Debug endpoint should show: `"mongodb_url_configured": true`
- Agent should show: `🟢 Backend Status: CONNECTED`

## 🔍 Troubleshooting

If you still see "disconnected" status:

1. **Check Vercel logs** for detailed error messages
2. **Verify environment variables** are set correctly
3. **Test MongoDB connection** locally first
4. **Check MongoDB Atlas** network access settings

## 🎯 Next Steps

1. Deploy the updated backend
2. Set your MongoDB environment variables
3. Test the health endpoint
4. Run your agent to verify connection

The agent will now show much clearer error messages if there are any remaining issues! 
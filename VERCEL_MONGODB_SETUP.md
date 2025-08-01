# MongoDB Setup for Vercel Deployment

This guide will help you properly configure MongoDB for your CyberRazor backend deployment on Vercel.

## 🔧 Quick Fix Steps

### 1. Set Environment Variables in Vercel

1. Go to your Vercel dashboard
2. Select your CyberRazor backend project
3. Go to **Settings** → **Environment Variables**
4. Add the following variables:

```
MONGODB_URL=mongodb+srv://your_username:your_password@your_cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB_NAME=cyberrazor
```

### 2. MongoDB Atlas Configuration

1. **Network Access**: 
   - Go to MongoDB Atlas → Network Access
   - Add IP Address: `0.0.0.0/0` (allows access from anywhere)
   - Or add Vercel's IP ranges if you prefer

2. **Database User**:
   - Go to Database Access
   - Ensure your user has read/write permissions
   - Use username/password authentication

3. **Cluster Status**:
   - Ensure your cluster is running
   - Check if it's in the correct region

### 3. Test Your Connection

Run the test script locally to verify your MongoDB connection:

```bash
cd backend
python test_vercel_env.py
```

### 4. Deploy and Verify

1. Deploy your updated backend to Vercel
2. Test the health endpoint: `https://your-backend.vercel.app/api/health`
3. Test the debug endpoint: `https://your-backend.vercel.app/api/debug`

## 🔍 Troubleshooting

### Common Issues

1. **"MONGODB_URL environment variable is not set"**
   - Solution: Add MONGODB_URL to Vercel environment variables

2. **"Authentication failed"**
   - Solution: Check username/password in your connection string
   - Ensure the database user exists and has correct permissions

3. **"Connection timeout"**
   - Solution: Check MongoDB Atlas network access settings
   - Ensure cluster is running and accessible

4. **"DNS resolution failed"**
   - Solution: Verify your MongoDB Atlas cluster URL is correct
   - Check if cluster name and domain are properly formatted

### Debugging Steps

1. **Check Vercel Logs**:
   - Go to Vercel dashboard → Functions
   - Check the function logs for error messages

2. **Test Health Endpoint**:
   ```bash
   curl https://your-backend.vercel.app/api/health
   ```

3. **Test Debug Endpoint**:
   ```bash
   curl https://your-backend.vercel.app/api/debug
   ```

4. **Verify Environment Variables**:
   - The debug endpoint will show if MONGODB_URL is configured
   - Check the URL preview to ensure it's correct

## 📋 Complete Setup Checklist

- [ ] MongoDB Atlas cluster created and running
- [ ] Database user created with read/write permissions
- [ ] Network access configured (0.0.0.0/0 or Vercel IPs)
- [ ] MONGODB_URL environment variable set in Vercel
- [ ] MONGODB_DB_NAME environment variable set (optional)
- [ ] Local connection test passed
- [ ] Backend deployed to Vercel
- [ ] Health endpoint returns "operational" status
- [ ] Agent shows "CONNECTED" status

## 🚀 After Setup

Once your MongoDB is properly configured:

1. Your backend will show "CONNECTED" status
2. The agent will display "🟢 Backend Status: CONNECTED"
3. All database operations will work correctly
4. Real-time threat reporting will function properly

## 🔐 Security Notes

- Never commit your MONGODB_URL to version control
- Use environment variables for all sensitive configuration
- Consider using MongoDB Atlas VPC peering for production
- Regularly rotate database passwords
- Monitor database access logs

## 📞 Support

If you're still having issues:

1. Check the Vercel function logs for detailed error messages
2. Verify your MongoDB Atlas cluster settings
3. Test the connection locally first
4. Ensure all environment variables are properly set

The updated backend now includes better error messages and debugging information to help identify connection issues quickly. 
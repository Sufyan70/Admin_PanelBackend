import React,{useState} from 'react'
import { useNavigate } from 'react-router-dom'

const Signup = () => {
    const [credentials, setCredentials] = useState({name:"", email: "", password: "",cpassword: "" })
    let navigate = useNavigate()


    const handleSubmit = async (e) => {
        e.preventDefault();
        const{name,email,password}=credentials;
        const response = await fetch("http://localhost:5000/api/auth/createuser", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ name,email,password}),
        });
        const json = await response.json();
        console.log(json);
        if (json.success) {
            //   Save the Auth token and redirect
            localStorage.setItem('token', json.authtoken)
            navigate("/")
        } else {
            alert("This Email is Already taken")
        }
    }

    const onChange = (e) => {
        setCredentials({ ...credentials, [e.target.name]: e.target.value })
    }

    return (
        <div className='container'>
            <form onSubmit={handleSubmit}>
                <div className="mb-3">
                    <label htmlFor="name" className="form-label">User Name</label>
                    <input type="text" className="form-control"  onChange={onChange} id="name" name='name' aria-describedby="emailHelp" />
                </div>
                <div className="mb-3">
                    <label htmlFor="email" className="form-label">Email address</label>
                    <input type="email" className="form-control"  onChange={onChange} id="email" name='email' aria-describedby="emailHelp" required />
                </div>
                <div className="mb-3">
                    <label htmlFor="password" className="form-label">Password</label>
                    <input type="password" className="form-control"  onChange={onChange} name='password' id="password" required minLength={5}/>
                </div>
                <div className="mb-3">
                    <label htmlFor="cpassword" className="form-label">Confirm Password</label>
                    <input type="password" className="form-control"  onChange={onChange} name='cpassword' id="cpassword" required minLength={5}/>
                </div>
                <button type="submit" className="btn btn-primary">Submit</button>
            </form>
        </div>
    )
}

export default Signup

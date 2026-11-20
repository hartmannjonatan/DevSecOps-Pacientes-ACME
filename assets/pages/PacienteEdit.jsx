import React, {useState, useEffect} from 'react';
import { Link, useParams } from 'react-router-dom'
import Layout from '../components/Layout';
import Swal from 'sweetalert2';
import axios from 'axios';

function PacienteEdit(){ //esse componente é responsável por retornar o formulário de atualização dos registros de um paciente
    //declarando states
    const [id, setId] = useState(useParams().id);
    const [nome, setNome] = useState('');
    const [cpf, setCpf] = useState('');
    const [oldCpf, setOldCpf] = useState('');
    const [sexo, setSexo] = useState('');
    const [endereco, setEndereco] = useState('');
    const [status, setStatus] = useState(true);
    const [dataNasc, setDataNasc] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    //quando o componente for renderizao (ou componente pai, ou quando seus states são alterados)
    useEffect(() => {
        axios.get('/api/show/'+id).then(function (response){ //api get recebe os dados de um paciente de acordo com seu id
            let paciente = response.data
            //seta os states com seus respectivos dados retornados pela api
            setNome(paciente.nome);
            setCpf(paciente.cpf);
            setOldCpf(paciente.cpf);
            setSexo(paciente.sexo);
            setEndereco(paciente.endereco);
            setStatus(paciente.status);
            setDataNasc(paciente.dataNasc)
        }).catch(function (error){
            //se houver erro é exibido um alert informando erro interno
            Swal.fire({
                icon: 'error',
                title: 'Ocorreu um erro interno...',
                showConfirmButton: false,
                timer: 1500
            })
        })
    }, [])

    const handleSave = async (event) => {
        event.preventDefault();
        setIsSaving(true);
        const formData = new FormData(event.currentTarget);
        try {
            await axios.post('/api/edit/'+id, formData);
            await Swal.fire({icon: 'success', title: 'Dados salvos com sucesso', timer: 1000, showConfirmButton: false});
            document.getElementById('btn-home').click();
        } catch (error) {
            const data = error.response?.data;
            Swal.fire({icon: 'error', title: 'Não foi possível salvar',
                text: data?.error || Object.values(data?.errors || {}).join(' ') || 'Verifique a conexão e tente novamente.'});
        } finally {
            setIsSaving(false);
        }
    }

    return ( //renderiza o componente criado
        <Layout>
            <div className="container">
                <h2 className="text-center text-light mt-5 mb-3">Atualizar registro de paciente</h2>
                <div className="card">
                    <div className="card-header">
                        <Link id='btn-home' className='btn btn-outline-info float-right' to={'/'}>Ver todos os pacientes</Link>
                    </div>
                    <div className="card-body">
                        <form onSubmit={handleSave}>
                            <div className="form-group">
                                <label htmlFor="nome">Nome:</label>
                                <input required type="text" maxLength={100} value={nome} className='form-control' id='nome' name='nome' onChange={(event)=>{setNome(event.target.value)}}/>
                                <label htmlFor="cpf">CPF:</label>
                                <input required type="text" maxLength={11} pattern="[0-9]{11}" value={cpf} className='form-control cpf' id='cpf' name='cpf' onChange={(event)=>{setCpf(event.target.value.replace(/[^0-9]/g, ''))}}/>
                                <label htmlFor="sexo">Sexo:</label>
                                <select required value={sexo} onChange={(event)=>{setSexo(document.getElementById("sexo").value)}} name="sexo" id="sexo" className="custom-select form-control">
                                    <option value="" disabled>Selecione seu sexo</option>
                                    <option value="Masculino">Masculino</option>
                                    <option value="Feminino">Feminino</option>
                                    <option value="Outro">Outro</option>
                                </select>
                                <label htmlFor="dataNasc">Data de Nascimento:</label>
                                <input required type="date" min="1000-01-01" value={dataNasc} className='form-control data' id='dataNasc' name='dataNasc' onChange={(event)=>{setDataNasc(event.target.value)}}/>
                                <label htmlFor="endereco">Endereço:</label>
                                <input required type="text" maxLength={255} value={endereco || ''} className='form-control' id='endereco' name='endereco' onChange={(event)=>{setEndereco(event.target.value)}}/>
                            </div>
                            <button disabled={isSaving} type="submit" className='btn btn-outline-primary mt-3'>
                                Atualizar Paciente
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </Layout>

    )
}

export default PacienteEdit; //exporta o componente PacienteEdit